package scenario

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// dSince is the release that gave the client ipv6_mode (docker-net-dhcp
// v2.2.0, #821); before it the D rows have nothing to judge.
var dSince = [3]int{2, 2, 0}

// dSettle is the wait between the lease event and the settled read
// (design row note: "read again after 20 s"); a variable so tests do
// not wait.
var dSettle = 20 * time.Second

// forever is how a lifetime of "forever" reads in addr6.
const forever = -1

// addr6 is one line of `ip -6 -o addr show`: lifetimes in seconds, or
// forever.
type addr6 struct {
	Addr        netip.Addr
	Bits        int
	Scope       string
	Valid, Pref int64
}

func parseLft(s string) (int64, error) {
	if s == "forever" {
		return forever, nil
	}
	return strconv.ParseInt(strings.TrimSuffix(s, "sec"), 10, 64)
}

// parseAddrs6 reads `ip -6 -o addr show`; a line it cannot read is an
// error, never skipped, so a changed iproute2 format cannot hide an
// address from the judge.
func parseAddrs6(out string) ([]addr6, error) {
	var res []addr6
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != "inet6" {
			continue
		}
		p, err := netip.ParsePrefix(f[3])
		if err != nil {
			return nil, fmt.Errorf("ip -6 addr line %q: %w", line, err)
		}
		a := addr6{Addr: p.Addr(), Bits: p.Bits(), Valid: forever, Pref: forever}
		seen := 0
		for i := 4; i+1 < len(f); i++ {
			switch f[i] {
			case "scope":
				a.Scope = f[i+1]
			case "valid_lft", "preferred_lft":
				n, err := parseLft(f[i+1])
				if err != nil {
					return nil, fmt.Errorf("ip -6 addr line %q: %w", line, err)
				}
				if f[i] == "valid_lft" {
					a.Valid = n
				} else {
					a.Pref = n
				}
				seen++
			}
		}
		if a.Scope == "" || seen != 2 {
			return nil, fmt.Errorf("ip -6 addr line %q carries no scope or lifetimes", line)
		}
		res = append(res, a)
	}
	return res, nil
}

func globals(as []addr6) []addr6 {
	var out []addr6
	for _, a := range as {
		if a.Scope == "global" {
			out = append(out, a)
		}
	}
	return out
}

func linkLocal(as []addr6) (netip.Addr, bool) {
	for _, a := range as {
		if a.Addr.IsLinkLocalUnicast() {
			return a.Addr, true
		}
	}
	return netip.Addr{}, false
}

func findAddr6(as []addr6, want netip.Addr) (addr6, bool) {
	for _, a := range as {
		if a.Addr == want {
			return a, true
		}
	}
	return addr6{}, false
}

// containerAddrs6 reads every IPv6 address in the container's own netns,
// the place the plugin's docs send an operator ("`ip -6 addr show` inside
// the container is where an operator reads all of this").
func containerAddrs6(ctx context.Context, r sourceadapter.Runner, name string) ([]addr6, error) {
	out, err := r.Run(ctx, fmt.Sprintf("sudo docker exec %s ip -6 -o addr show", name))
	if err != nil {
		return nil, fmt.Errorf("docker exec %s ip -6 addr: %w", name, err)
	}
	return parseAddrs6(out)
}

// parseDefaultRoute6 reads the gateway of `ip -6 route show default`.
func parseDefaultRoute6(out string) (netip.Addr, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[0] == "default" && f[i] == "via" {
				a, err := netip.ParseAddr(f[i+1])
				return a, err == nil
			}
		}
	}
	return netip.Addr{}, false
}

func containerRoute6(ctx context.Context, r sourceadapter.Runner, name string) (netip.Addr, bool, string, error) {
	out, err := r.Run(ctx, fmt.Sprintf("sudo docker exec %s ip -6 route show default", name))
	if err != nil {
		return netip.Addr{}, false, "", fmt.Errorf("docker exec %s ip -6 route: %w", name, err)
	}
	gw, ok := parseDefaultRoute6(out)
	return gw, ok, strings.TrimSpace(out), nil
}

// healthEndpoint is the part of one /Plugin.Health endpoints entry the
// lab reads (plugin docs/reference.md, "Plugin.Health").
type healthEndpoint struct {
	Endpoint             string `json:"endpoint"`
	IPv6TemporaryAddress string `json:"ipv6_temporary_address"`
	// DelegatedPrefixes (v2.5.0, prefix delegation) and NAT64Prefixes (v2.4.0, PREF64) are
	// absent when there are none (docs/reference.md, "Plugin.Health").
	DelegatedPrefixes []healthPrefix `json:"delegated_prefixes"`
	NAT64Prefixes     []string       `json:"nat64_prefixes"`
}

type healthPrefix struct {
	Prefix string `json:"prefix"`
}

// pluginHealthCmd is the plugin docs' own recipe: GET on the plugin
// socket, as root because /run/docker/plugins is root-only.
var pluginHealthCmd = fmt.Sprintf(`id=$(sudo docker plugin inspect -f '{{.Id}}' %s) && sudo curl -sf --unix-socket /run/docker/plugins/$id/net-dhcp.sock http://localhost/Plugin.Health`, pluginAlias)

// parseHealthEndpoint finds endpointID in a /Plugin.Health body; either
// id may be the other's 12-character short form.
func parseHealthEndpoint(body, endpointID string) (healthEndpoint, bool, error) {
	var h struct {
		Endpoints []healthEndpoint `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		return healthEndpoint{}, false, fmt.Errorf("/Plugin.Health is not JSON: %w", err)
	}
	if len(endpointID) < 12 {
		return healthEndpoint{}, false, fmt.Errorf("endpoint id %q is too short to match", endpointID)
	}
	for _, ep := range h.Endpoints {
		if len(ep.Endpoint) >= 12 && (strings.HasPrefix(ep.Endpoint, endpointID) || strings.HasPrefix(endpointID, ep.Endpoint)) {
			return ep, true, nil
		}
	}
	return healthEndpoint{}, false, nil
}

func pluginHealth(ctx context.Context, r sourceadapter.Runner, endpointID, path string) (healthEndpoint, bool, error) {
	out, err := pluginHealthBody(ctx, r, path)
	if err != nil {
		return healthEndpoint{}, false, err
	}
	return parseHealthEndpoint(out, endpointID)
}

// pluginHealthBody reads /Plugin.Health once and keeps it at path.
func pluginHealthBody(ctx context.Context, r sourceadapter.Runner, path string) (string, error) {
	out, err := r.Run(ctx, pluginHealthCmd)
	if err != nil {
		return "", fmt.Errorf("read /Plugin.Health: %w", err)
	}
	return out, os.WriteFile(path, []byte(out), 0o644)
}

// healthCounter is one top-level /Plugin.Health counter, such as
// dhcpv6_auto_fallbacks (docs/reference.md field table, D3c).
func healthCounter(body, name string) (int64, bool) {
	var h map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &h) != nil {
		return 0, false
	}
	var n int64
	if raw, ok := h[name]; !ok || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}

// eui64 is prefix plus the modified EUI-64 of mac (RFC 4291 appendix A),
// the plugin's default ipv6_iid (docs/reference.md: "`eui64` (the
// default ...) is the modified EUI-64 of the endpoint's MAC").
func eui64(p netip.Prefix, mac string) (netip.Addr, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return netip.Addr{}, fmt.Errorf("MAC %q is not a 48-bit address", mac)
	}
	if p.Bits() != 64 || !p.Addr().Is6() {
		return netip.Addr{}, fmt.Errorf("prefix %s is not a /64", p)
	}
	b := p.Masked().Addr().As16()
	copy(b[8:], []byte{hw[0] ^ 0x02, hw[1], hw[2], 0xff, 0xfe, hw[3], hw[4], hw[5]})
	return netip.AddrFrom16(b), nil
}

// v6Ident is the decoder's ident set for one container: its MAC and its
// link-local, whichever exist ("-" when neither). docker reports no MAC
// under ipvlan, whose frames carry the parent's, so one container per row
// bounds what else can match (design defeat A2).
func v6Ident(mac string, ll netip.Addr) string {
	var parts []string
	if mac != "" {
		parts = append(parts, strings.ToLower(mac))
	}
	if ll.IsValid() {
		parts = append(parts, ll.String())
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

func msgs6After(msgs []DHCP6Msg, from time.Time) []DHCP6Msg {
	var out []DHCP6Msg
	for _, m := range msgs {
		if !m.At.Before(from) {
			out = append(out, m)
		}
	}
	return out
}

func rasAfter(ras []RAMsg, from time.Time) []RAMsg {
	var out []RAMsg
	for _, r := range ras {
		if !r.At.Before(from) {
			out = append(out, r)
		}
	}
	return out
}

// dCapture reads the DHCPv6 messages and RAs the capture holds since
// from, re-reading until ready or fCaptureWait passes, and keeps the
// decoded log as evidence under label.
func dCapture(ctx context.Context, e Env, scenario, label, ident string, from time.Time, ready func([]DHCP6Msg, []RAMsg) bool, ev map[string]string) ([]DHCP6Msg, []RAMsg, error) {
	rd, ok := e.Capture.(V6Reader)
	if !ok {
		return nil, nil, errors.New("this run's capture reader cannot read DHCPv6 or router advertisements")
	}
	snap := strings.TrimSuffix(evidencePath(e, scenario, label), ".txt") + ".pcap"
	deadline := time.Now().Add(fCaptureWait)
	for {
		all, allRA, err := rd.Messages6(ctx, ident, snap)
		if err != nil {
			return nil, nil, err
		}
		msgs, ras := msgs6After(all, from), rasAfter(allRA, from)
		if ready(msgs, ras) || time.Now().After(deadline) {
			logPath := evidencePath(e, scenario, label)
			if err := writeMessageLog6(logPath, msgs, ras); err != nil {
				return nil, nil, err
			}
			ev[label] = logPath
			return msgs, ras, nil
		}
		if err := sleepCtx(ctx, fCapturePoll); err != nil {
			return nil, nil, err
		}
	}
}

func writeMessageLog6(path string, msgs []DHCP6Msg, ras []RAMsg) error {
	var b strings.Builder
	for _, m := range msgs {
		fmt.Fprintf(&b, "%s %s xid=%s client=%s server=%s rapid=%v NA=%v TA=%v PD=%v %s>%s\n",
			m.At.UTC().Format(time.RFC3339Nano), m.Type, m.XID, m.ClientDUID, m.ServerDUID, m.Rapid, m.NA, m.TA, m.PD, m.Src, m.Dst)
	}
	for _, r := range ras {
		fmt.Fprintf(&b, "%s RA %s M=%v O=%v lifetime=%d PIOs=%v PREF64=%v\n",
			r.At.UTC().Format(time.RFC3339Nano), r.Src, r.Managed, r.Other, r.RouterLifetime, r.PIOs, r.Pref64)
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// writeAddrs6 keeps one container read as evidence.
func writeAddrs6(path string, as []addr6, route string) error {
	var b strings.Builder
	for _, a := range as {
		fmt.Fprintf(&b, "%s/%d scope %s valid %d pref %d\n", a.Addr, a.Bits, a.Scope, a.Valid, a.Pref)
	}
	fmt.Fprintf(&b, "route: %s\n", route)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
