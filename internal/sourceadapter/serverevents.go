package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ServerEvent is one DHCPv4 message a source logged (lab #15). Type uses
// the spelling of scenario.DHCPMsg (DISCOVER, OFFER, REQUEST, ACK, NAK,
// DECLINE, RELEASE, INFORM), so the two compare later. At is the source
// VM's clock and is for ordering inside one source only; TID is Kea's
// transaction id and empty on the other servers, which log none. IP is
// empty on a line that names none (a DISCOVER).
type ServerEvent struct {
	At   time.Time
	Type string
	MAC  string
	IP   string
	TID  string
}

// ErrJournalSuppressed means journald dropped lines from the unit under
// rate limiting, so any count over the rest would be short (lab #15).
var ErrJournalSuppressed = errors.New("the journal reports suppressed messages")

// journalReader is how a server's log lines become events: parse returns
// ok=false for a line that is not a DHCP message of this server, and an
// error for a line of a known shape that does not parse (lab #15).
type journalReader func(line string) (ev ServerEvent, ok bool, err error)

var suppressedRE = regexp.MustCompile(`Suppressed [0-9]+ messages? from`)

// journalSinceLayout is the only form `since` takes on the command line;
// a typed time has no quote or space to inject (lab #15).
const journalSinceLayout = "2006-01-02 15:04:05"

// serverEventsCmd renders the journal read. The unit is the host's own
// constant and since is formatted from a time.Time, so no caller string
// reaches the shell.
func serverEventsCmd(unit string, since time.Time) string {
	return fmt.Sprintf("sudo journalctl -u %s -o short-iso --no-pager --since '%s UTC'", unit, since.UTC().Format(journalSinceLayout))
}

// serverEvents is every Debian adapter's ServerEvents body. The filter on
// mac runs here, on parsed lines, so the argument never reaches the
// source; mac passes validateMAC first.
func (h host) serverEvents(ctx context.Context, r Runner, since time.Time, mac string, read journalReader) ([]ServerEvent, error) {
	if since.IsZero() {
		return nil, errors.New("server events: since is the zero time, which would read the whole journal")
	}
	if mac != "" {
		var err error
		if mac, err = validateMAC(mac); err != nil {
			return nil, err
		}
	}
	unit := h.svc().name
	out, err := r.Run(ctx, serverEventsCmd(unit, since))
	if err != nil {
		return nil, fmt.Errorf("server events: journalctl -u %s: %w", unit, err)
	}
	var events []ServerEvent
	for _, line := range strings.Split(out, "\n") {
		if suppressedRE.MatchString(line) {
			return nil, fmt.Errorf("server events: %s: %w: %q", unit, ErrJournalSuppressed, line)
		}
		ev, ok, err := read(line)
		if err != nil {
			return nil, fmt.Errorf("server events: %s: %w", unit, err)
		}
		if !ok || (mac != "" && ev.MAC != mac) {
			continue
		}
		events = append(events, ev)
	}
	return events, nil
}

var journalTimeLayouts = []string{"2006-01-02T15:04:05-0700", "2006-01-02T15:04:05.999999-0700", time.RFC3339Nano}

// journalTime reads the leading `-o short-iso` timestamp of a line.
func journalTime(line string) (time.Time, error) {
	field, _, _ := strings.Cut(line, " ")
	for _, layout := range journalTimeLayouts {
		if t, err := time.Parse(layout, field); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("journal line has no short-iso timestamp: %q", line)
}

var (
	ipv4RE = regexp.MustCompile(`\b[0-9]{1,3}(?:\.[0-9]{1,3}){3}\b`)
	macRE  = `[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}`
)

// A Kea per-packet message names its identifier, the client as
// `[hwtype=1 aa:..]` and, mostly, `tid=0x..`; their order differs per
// message, so each is found on its own.
var (
	keaIDRE  = regexp.MustCompile(`\b(DHCP4_[A-Z0-9_]+)\b`)
	keaHWRE  = regexp.MustCompile(`\[hwtype=[0-9]+ (` + macRE + `)\]`)
	keaTIDRE = regexp.MustCompile(`\btid=(0x[0-9a-fA-F]+)`)
)

// keaTypes maps the Kea messages logged at INFO to the packet they stand
// for; DISCOVER and REQUEST appear only at DEBUG, which the lab does not
// raise (lab #15). DHCP4_PACKET_NAK_* is matched by prefix.
var keaTypes = map[string]string{
	"DHCP4_LEASE_ALLOC":   "ACK",
	"DHCP4_LEASE_ADVERT":  "OFFER",
	"DHCP4_LEASE_OFFER":   "OFFER",
	"DHCP4_RELEASE":       "RELEASE",
	"DHCP4_DECLINE_LEASE": "DECLINE",
}

// keaReuse is logged when lease caching answers a client; which packet it
// stands for is unmeasured, so it fails the read rather than vanish (lab #15).
const keaReuse = "DHCP4_LEASE_REUSE"

func keaJournal(line string) (ServerEvent, bool, error) {
	id := keaIDRE.FindStringSubmatchIndex(line)
	if id == nil {
		return ServerEvent{}, false, nil
	}
	name := line[id[2]:id[3]]
	if name == keaReuse {
		return ServerEvent{}, false, fmt.Errorf("kea logs %s, a lease-cache message whose packet type is not measured on this lab: %q", name, line)
	}
	typ, ok := keaTypes[name]
	nak := strings.HasPrefix(name, "DHCP4_PACKET_NAK_")
	if nak {
		typ, ok = "NAK", true
	}
	if !ok {
		return ServerEvent{}, false, nil
	}
	rest := line[id[1]:]
	hw := keaHWRE.FindStringSubmatch(rest)
	if hw == nil {
		return ServerEvent{}, false, fmt.Errorf("kea %s line carries no [hwtype=N mac]: %q", name, line)
	}
	at, err := journalTime(line)
	if err != nil {
		return ServerEvent{}, false, err
	}
	ev := ServerEvent{At: at, Type: typ, MAC: strings.ToLower(hw[1])}
	if t := keaTIDRE.FindStringSubmatch(rest); t != nil {
		ev.TID = t[1]
	}
	// A NAK text quotes the request's 0.0.0.0 source, not an address.
	if !nak {
		ev.IP = ipv4RE.FindString(rest)
	}
	return ev, true, nil
}

// iscMsgRE splits a dhcpd syslog line into the type and the tail that
// starts at its first preposition; the address and the hardware address
// are read from the tail by their own prefix words, which differ per
// type (`on A to M`, `for A from M`, `of A from M`, `from M`).
var (
	iscMsgRE = regexp.MustCompile(`\bDHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|RELEASE|DECLINE) ((?:on|for|of|from|to) .*)$`)
	iscIPRE  = regexp.MustCompile(`\b(?:on|for|of) ([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)
	iscMACRE = regexp.MustCompile(`\b(?:from|to) (` + macRE + `)\b`)
)

func iscJournal(line string) (ServerEvent, bool, error) {
	m := iscMsgRE.FindStringSubmatch(line)
	if m == nil {
		return ServerEvent{}, false, nil
	}
	mac := iscMACRE.FindStringSubmatch(m[2])
	if mac == nil {
		return ServerEvent{}, false, fmt.Errorf("dhcpd DHCP%s line carries no hardware address: %q", m[1], line)
	}
	ip := ""
	if x := iscIPRE.FindStringSubmatch(m[2]); x != nil {
		ip = x[1]
	}
	at, err := journalTime(line)
	if err != nil {
		return ServerEvent{}, false, err
	}
	return ServerEvent{At: at, Type: m[1], MAC: strings.ToLower(mac[1]), IP: ip}, true, nil
}

// dnsmasqAnchorRE finds a dnsmasq DHCP line by `DHCPTYPE(interface)`. The
// same unit logs DHCPv6, whose REQUEST, RELEASE and DECLINE reuse the v4
// names and are followed by a DUID or a v6 address (colon-separated hex
// of more than six bytes), so the v4 shape is told apart by what follows
// the interface: an optional IPv4 address, then a six-byte MAC that ends
// the token.
var (
	dnsmasqAnchorRE = regexp.MustCompile(`\bDHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|RELEASE|DECLINE|INFORM)\([^)]+\) ?(\S*)`)
	dnsmasqMsgRE    = regexp.MustCompile(`\bDHCP(DISCOVER|OFFER|REQUEST|ACK|NAK|RELEASE|DECLINE|INFORM)\([^)]+\) (?:([0-9]{1,3}(?:\.[0-9]{1,3}){3}) )?(` + macRE + `)(?:\s|$)`)
)

func dnsmasqJournal(line string) (ServerEvent, bool, error) {
	a := dnsmasqAnchorRE.FindStringSubmatch(line)
	if a == nil {
		return ServerEvent{}, false, nil
	}
	m := dnsmasqMsgRE.FindStringSubmatch(line)
	if m == nil {
		// A first token that holds a colon but is not a six-byte MAC is a
		// DHCPv6 DUID or address: not a v4 event, and not an error.
		if strings.Contains(a[2], ":") {
			return ServerEvent{}, false, nil
		}
		return ServerEvent{}, false, fmt.Errorf("dnsmasq DHCP line has no hardware address after the interface: %q", line)
	}
	at, err := journalTime(line)
	if err != nil {
		return ServerEvent{}, false, err
	}
	return ServerEvent{At: at, Type: m[1], MAC: strings.ToLower(m[3]), IP: m[2]}, true, nil
}

func (a *KeaAdapter) ServerEvents(ctx context.Context, since time.Time, mac string) ([]ServerEvent, error) {
	return a.host().serverEvents(ctx, a.Runner, since, mac, keaJournal)
}

func (a *ISCDHCPAdapter) ServerEvents(ctx context.Context, since time.Time, mac string) ([]ServerEvent, error) {
	return a.host().serverEvents(ctx, a.Runner, since, mac, iscJournal)
}

func (a *DnsmasqAdapter) ServerEvents(ctx context.Context, since time.Time, mac string) ([]ServerEvent, error) {
	return a.host().serverEvents(ctx, a.Runner, since, mac, dnsmasqJournal)
}

// serverEventsNA is the reason the sources without a journal reader give
// for the absent capability (lab #15, #13, #14).
const serverEventsNA = "the lab reads a source's DHCP log only from a systemd journal, and this source has no reader yet"

// serverEventsRefused is the ServerEvents body of every source that does
// not declare CapServerEvents.
func serverEventsRefused(label string) ([]ServerEvent, error) {
	return nil, fmt.Errorf("%s: %s", label, serverEventsNA)
}
