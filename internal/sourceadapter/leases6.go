package sourceadapter

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Lease6Type is the IA a DHCPv6 lease belongs to (RFC 8415 section 21.4
// IA_NA, 21.5 IA_TA).
type Lease6Type string

const (
	Lease6NA Lease6Type = "na"
	Lease6TA Lease6Type = "ta"
)

// Lease6 is one active IA_NA or IA_TA address from a source's own DHCPv6
// table (#23 group D). DUID is the client's, lowercase colon-hex.
// Preferred and Valid are zero when the table does not state them
// (dnsmasq keeps only the expiry); Expires is zero when the table gives
// none or "never".
type Lease6 struct {
	Type      Lease6Type
	Address   netip.Addr
	DUID      string
	IAID      uint32
	Preferred time.Duration
	Valid     time.Duration
	Expires   time.Time
}

func sortLeases6(ls []Lease6) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].Address.Less(ls[j].Address) })
}

// keaLease6Cmd asks the control agent for the dhcp6 service's table; the
// agent forwards it to the dhcp6 control socket (cloud-init/kea-user-data).
const keaLease6Cmd = `curl -sf -X POST -H "Content-Type: application/json" ` +
	`-d '{"command":"lease6-get-all","service":["dhcp6"]}' http://127.0.0.1:8000/`

type keaLease6Response struct {
	Result    int `json:"result"`
	Arguments struct {
		Leases []struct {
			IPAddress string `json:"ip-address"`
			DUID      string `json:"duid"`
			IAID      uint32 `json:"iaid"`
			Type      string `json:"type"`
			State     int    `json:"state"`
			CLTT      int64  `json:"cltt"`
			ValidLft  int64  `json:"valid-lft"`
			PrefLft   int64  `json:"preferred-lft"`
		} `json:"leases"`
	} `json:"arguments"`
}

// parseKeaLeases6 reads a lease6-get-all reply: the control agent's
// array, or the bare object the dhcp6 socket itself returns. Result 3 is
// an empty table; any other non-zero result or a reply that does not
// parse is an error, never zero leases.
func parseKeaLeases6(raw string) ([]Lease6, error) {
	var resp []keaLease6Response
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") {
		trimmed = "[" + trimmed + "]"
	}
	if err := json.Unmarshal([]byte(trimmed), &resp); err != nil {
		return nil, fmt.Errorf("kea: lease6 reply did not parse as JSON: %w", err)
	}
	if len(resp) == 0 {
		return nil, fmt.Errorf("kea: lease6 reply had no service entries")
	}
	switch resp[0].Result {
	case 0, 3:
	default:
		return nil, fmt.Errorf("kea: lease6 reply returned result=%d", resp[0].Result)
	}
	out := []Lease6{}
	for _, l := range resp[0].Arguments.Leases {
		if l.State != 0 || (l.CLTT != 0 && l.ValidLft == 0) {
			continue
		}
		var typ Lease6Type
		switch l.Type {
		case "IA_NA":
			typ = Lease6NA
		case "IA_TA":
			typ = Lease6TA
		default:
			continue
		}
		a, err := netip.ParseAddr(l.IPAddress)
		if err != nil || !a.Is6() {
			return nil, fmt.Errorf("kea: lease6 address %q is not IPv6", l.IPAddress)
		}
		ls := Lease6{Type: typ, Address: a, DUID: strings.ToLower(l.DUID), IAID: l.IAID,
			Preferred: time.Duration(l.PrefLft) * time.Second, Valid: time.Duration(l.ValidLft) * time.Second}
		if l.ValidLft > 0 && l.CLTT > 0 {
			ls.Expires = time.Unix(l.CLTT+l.ValidLft, 0).UTC()
		}
		out = append(out, ls)
	}
	sortLeases6(out)
	return out, nil
}

// iscLease6File is dhcpd -6's lease table on Debian (LEASES of the -6
// instance in /etc/init.d/isc-dhcp-server, measured 2026-10-09 #23).
const iscLease6File = "/var/lib/dhcp/dhcpd6.leases"

var (
	iscIAStartRE  = regexp.MustCompile(`(?m)^ia-(na|ta|pd)\s+"`)
	iscIABlockRE  = regexp.MustCompile(`(?s)(?m)^ia-(na|ta|pd)\s+"((?:[^"\\]|\\.)*)"\s*\{(.*?)\n\}`)
	iscIAAddrRE   = regexp.MustCompile(`(?s)iaaddr\s+([0-9a-fA-F:]+)\s*\{(.*?)\}`)
	iscPrefLifeRE = regexp.MustCompile(`preferred-life\s+(\d+);`)
	iscMaxLifeRE  = regexp.MustCompile(`max-life\s+(\d+);`)
	iscBigEndRE   = regexp.MustCompile(`(?m)^authoring-byte-order\s+big-endian;`)
)

// parseISCLeases6 reads dhcpd6.leases(5): each ia-na/ia-ta block's quoted
// key is the 4-byte IAID in the authoring byte order, then the client
// DUID; each iaaddr inside carries its binding state and lifetimes. The
// last block per IA and address wins (dhcpd appends). ia-pd blocks are
// counted for truncation but not returned. A block count that does not
// match the blocks parsed is a truncated file, an error.
func parseISCLeases6(raw string) ([]Lease6, error) {
	starts := iscIAStartRE.FindAllStringIndex(raw, -1)
	blocks := iscIABlockRE.FindAllStringSubmatch(raw, -1)
	if len(blocks) != len(starts) {
		return nil, fmt.Errorf("isc-dhcp: %d ia block(s) opened but only %d parsed cleanly; dhcpd6.leases looks truncated", len(starts), len(blocks))
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if iscBigEndRE.MatchString(raw) {
		order = binary.BigEndian
	}
	type key struct {
		t Lease6Type
		a netip.Addr
	}
	byKey := map[key]Lease6{}
	for _, b := range blocks {
		if b[1] == "pd" {
			continue
		}
		id, err := decodeISCQuotedString(b[2])
		if err != nil {
			return nil, fmt.Errorf("isc-dhcp: ia key: %w", err)
		}
		if len(id) < 5 {
			return nil, fmt.Errorf("isc-dhcp: ia key is %d bytes, want the 4-byte IAID and a DUID", len(id))
		}
		typ := Lease6Type(b[1])
		for _, m := range iscIAAddrRE.FindAllStringSubmatch(b[3], -1) {
			a, err := netip.ParseAddr(m[1])
			if err != nil || !a.Is6() {
				return nil, fmt.Errorf("isc-dhcp: iaaddr %q is not IPv6", m[1])
			}
			k := key{typ, a}
			if s := iscStateRE.FindStringSubmatch(m[2]); len(s) == 2 && s[1] != "active" {
				delete(byKey, k)
				continue
			}
			l := Lease6{Type: typ, Address: a, DUID: hexColon(id[4:]), IAID: order.Uint32(id[:4])}
			if s := iscPrefLifeRE.FindStringSubmatch(m[2]); len(s) == 2 {
				n, _ := strconv.ParseInt(s[1], 10, 64)
				l.Preferred = time.Duration(n) * time.Second
			}
			if s := iscMaxLifeRE.FindStringSubmatch(m[2]); len(s) == 2 {
				n, _ := strconv.ParseInt(s[1], 10, 64)
				l.Valid = time.Duration(n) * time.Second
			}
			if s := iscEndsRE.FindStringSubmatch(m[2]); len(s) == 2 {
				if t, err := time.Parse("2006/01/02 15:04:05", s[1]); err == nil {
					l.Expires = t.UTC()
				}
			}
			byKey[k] = l
		}
	}
	out := make([]Lease6, 0, len(byKey))
	for _, l := range byKey {
		out = append(out, l)
	}
	sortLeases6(out)
	return out, nil
}

// parseDnsmasqLeases6 reads the v6 half of dnsmasq.leases: the lines after
// "duid <server duid>", each "<expiry> <iaid, T-prefixed for IA_TA>
// <address> <hostname> <client duid>" (dnsmasq 2.91, measured 2026-10-09
// #23). Expiry 0 is infinite.
func parseDnsmasqLeases6(raw string) ([]Lease6, error) {
	out := []Lease6{}
	inV6 := false
	for i, line := range strings.Split(strings.TrimRight(raw, "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "duid" {
			inV6 = true
			continue
		}
		if !inV6 {
			continue
		}
		if len(fields) < 5 {
			return nil, fmt.Errorf("dnsmasq: v6 lease line %d has %d field(s), want 5: %q", i+1, len(fields), line)
		}
		typ, iaid := Lease6NA, fields[1]
		if strings.HasPrefix(iaid, "T") {
			typ, iaid = Lease6TA, iaid[1:]
		}
		n, err := strconv.ParseUint(iaid, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("dnsmasq: v6 lease line %d: IAID %q: %w", i+1, fields[1], err)
		}
		a, err := netip.ParseAddr(fields[2])
		if err != nil || !a.Is6() {
			return nil, fmt.Errorf("dnsmasq: v6 lease line %d: address %q is not IPv6", i+1, fields[2])
		}
		l := Lease6{Type: typ, Address: a, DUID: strings.ToLower(fields[4]), IAID: uint32(n)}
		if epoch, err := strconv.ParseInt(fields[0], 10, 64); err == nil && epoch > 0 {
			l.Expires = time.Unix(epoch, 0).UTC()
		}
		out = append(out, l)
	}
	sortLeases6(out)
	return out, nil
}

// validateAddr6 is validateAddr's IPv6 twin: only stdlib's normalized
// form of a real IPv6 literal reaches a command line.
func validateAddr6(addr string) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if !a.Is6() || a.Is4In6() || a.Zone() != "" {
		return "", fmt.Errorf("address %q is not a zoneless IPv6 address", addr)
	}
	return a.String(), nil
}
