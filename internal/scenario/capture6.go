package scenario

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// IA6 is one entry of an IA in a DHCPv6 message: Addr for IA_NA and
// IA_TA, Prefix for IA_PD, both invalid for an IA that carries none.
type IA6 struct {
	IAID        uint32
	Addr        netip.Addr
	Prefix      netip.Prefix
	Pref, Valid uint32
}

// DHCP6Msg is one DHCPv6 message as dhcp6_message_log prints it (#23
// group D). Rapid is option 14 (RFC 8415 section 18.3.1).
type DHCP6Msg struct {
	At                     time.Time
	Type, XID              string
	ClientDUID, ServerDUID string
	Rapid                  bool
	NA, TA, PD             []IA6
	Src, Dst               netip.Addr
}

// HasAddr reports whether ias grant at least one address or prefix.
func HasAddr(ias []IA6) bool {
	for _, ia := range ias {
		if ia.Addr.IsValid() || ia.Prefix.IsValid() {
			return true
		}
	}
	return false
}

// PIO is one prefix information option (RFC 4861 section 4.6.2).
type PIO struct {
	Prefix      netip.Prefix
	Auto        bool
	Valid, Pref uint32
}

// RAMsg is one router advertisement; Pref64 is RFC 8781's option.
type RAMsg struct {
	At              time.Time
	Src             netip.Addr
	Managed, Other  bool
	RouterLifetime  uint32
	PIOs            []PIO
	Pref64          []netip.Prefix
	Pref64Lifetimes []uint32
}

// V6Reader is the capture reader's IPv6 view (#23 group D). A
// CaptureReader that cannot offer it leaves a group D scenario BLOCKED.
type V6Reader interface {
	Messages6(ctx context.Context, ident, snapshotPath string) ([]DHCP6Msg, []RAMsg, error)
}

// Messages6 snapshots the live capture and decodes it with the repo's
// own dhcp6_message_log. ident is a comma set of MAC, link-local, DUID.
func (o ObserverCapture) Messages6(ctx context.Context, ident, snapshotPath string) ([]DHCP6Msg, []RAMsg, error) {
	if err := o.snapshot(ctx, snapshotPath); err != nil {
		return nil, nil, err
	}
	script := o.RepoRoot + "/scripts/dhcp-exchange-check.sh"
	cmd := exec.CommandContext(ctx, "bash", "-c", `. "$1"; dhcp6_message_log "$2" "$3"`,
		"dhcp6-message-log-wrapper", script, snapshotPath, ident)
	out, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("dhcp6_message_log: %w", err)
	}
	return parseMessageLog6(string(out))
}

func parseTS(s string) (time.Time, error) {
	ts, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp %q: %w", s, err)
	}
	sec := int64(ts)
	return time.Unix(sec, int64((ts-float64(sec))*1e9)), nil
}

func parseU32(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err
}

// parseIAs reads "iaid|addr|pref|valid" entries, comma-joined, "-" none.
func parseIAs(field string, pd bool) ([]IA6, error) {
	if field == "-" {
		return nil, nil
	}
	var out []IA6
	for _, e := range strings.Split(field, ",") {
		p := strings.Split(e, "|")
		if len(p) != 4 {
			return nil, fmt.Errorf("IA entry %q: want iaid|addr|pref|valid", e)
		}
		id, err := parseU32(p[0])
		if err != nil {
			return nil, fmt.Errorf("IA entry %q: %w", e, err)
		}
		ia := IA6{IAID: id}
		if p[1] != "-" {
			if pd {
				ia.Prefix, err = netip.ParsePrefix(p[1])
			} else {
				ia.Addr, err = netip.ParseAddr(p[1])
			}
			if err != nil {
				return nil, fmt.Errorf("IA entry %q: %w", e, err)
			}
			if ia.Pref, err = parseU32(p[2]); err != nil {
				return nil, fmt.Errorf("IA entry %q: %w", e, err)
			}
			if ia.Valid, err = parseU32(p[3]); err != nil {
				return nil, fmt.Errorf("IA entry %q: %w", e, err)
			}
		}
		out = append(out, ia)
	}
	return out, nil
}

func parseRA(f []string) (RAMsg, error) {
	var ra RAMsg
	var err error
	if len(f) != 8 {
		return ra, fmt.Errorf("RA line has %d fields, want 8", len(f))
	}
	if ra.At, err = parseTS(f[0]); err != nil {
		return ra, err
	}
	if ra.Src, err = netip.ParseAddr(f[2]); err != nil {
		return ra, err
	}
	ra.Managed, ra.Other = f[3] == "1", f[4] == "1"
	if ra.RouterLifetime, err = parseU32(f[5]); err != nil {
		return ra, err
	}
	if f[6] != "-" {
		for _, e := range strings.Split(f[6], ",") {
			p := strings.Split(e, "|")
			if len(p) != 4 {
				return ra, fmt.Errorf("PIO %q: want prefix|A|valid|pref", e)
			}
			pio := PIO{Auto: p[1] == "1"}
			if pio.Prefix, err = netip.ParsePrefix(p[0]); err != nil {
				return ra, err
			}
			if pio.Valid, err = parseU32(p[2]); err != nil {
				return ra, err
			}
			if pio.Pref, err = parseU32(p[3]); err != nil {
				return ra, err
			}
			ra.PIOs = append(ra.PIOs, pio)
		}
	}
	if f[7] != "-" {
		for _, e := range strings.Split(f[7], ",") {
			pfx, life, ok := strings.Cut(e, "|")
			if !ok {
				return ra, fmt.Errorf("PREF64 %q: want prefix|lifetime", e)
			}
			p, err := netip.ParsePrefix(pfx)
			if err != nil {
				return ra, err
			}
			l, err := parseU32(life)
			if err != nil {
				return ra, err
			}
			ra.Pref64, ra.Pref64Lifetimes = append(ra.Pref64, p), append(ra.Pref64Lifetimes, l)
		}
	}
	return ra, nil
}

// parseMessageLog6 reads dhcp6_message_log's two line shapes.
func parseMessageLog6(out string) ([]DHCP6Msg, []RAMsg, error) {
	var msgs []DHCP6Msg
	var ras []RAMsg
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 1 && f[1] == "RA" {
			ra, err := parseRA(f)
			if err != nil {
				return nil, nil, fmt.Errorf("dhcp6_message_log %q: %w", line, err)
			}
			ras = append(ras, ra)
			continue
		}
		if len(f) != 11 {
			return nil, nil, fmt.Errorf("dhcp6_message_log line has %d fields, want 11: %q", len(f), line)
		}
		m := DHCP6Msg{Type: f[1], XID: f[2], Rapid: f[5] == "1"}
		var err error
		if m.At, err = parseTS(f[0]); err != nil {
			return nil, nil, err
		}
		if f[3] != "-" {
			m.ClientDUID = f[3]
		}
		if f[4] != "-" {
			m.ServerDUID = f[4]
		}
		for i, dst := range []*[]IA6{&m.NA, &m.TA, &m.PD} {
			if *dst, err = parseIAs(f[6+i], i == 2); err != nil {
				return nil, nil, fmt.Errorf("dhcp6_message_log %q: %w", line, err)
			}
		}
		if m.Src, err = netip.ParseAddr(f[9]); err != nil {
			return nil, nil, fmt.Errorf("dhcp6_message_log %q: %w", line, err)
		}
		if m.Dst, err = netip.ParseAddr(f[10]); err != nil {
			return nil, nil, fmt.Errorf("dhcp6_message_log %q: %w", line, err)
		}
		msgs = append(msgs, m)
	}
	return msgs, ras, nil
}
