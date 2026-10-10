package sourceadapter

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ForceRenewParams is one FORCERENEW to send (F8-forcerenew, #21). Mode is
// "unsigned", "badkey" or "signed"; Server is the ACK's option 54;
// AckReplay is the replay value of the ACK's option 90, which the
// sender raises by 1 (badkey) or 2 (signed), RFC 3118 section 2.
type ForceRenewParams struct {
	Mode      string
	Addr      string
	CHAddr    string
	ClientID  string
	Server    string
	Nonce     []byte
	AckReplay uint64
	// Offlink sends to the source's next hop for Addr, not to Addr's own
	// MAC: behind a relay the client is on another subnet (#11, F8).
	Offlink bool
}

const forceRenewScriptPath = "/run/lab/forcerenew-send.py"

var routeViaRE = regexp.MustCompile(`\bvia ([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b`)

var neighMACRE = regexp.MustCompile(`\blladdr ([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b`)

// sendForceRenew is every adapter's SendForceRenew body. The frame goes
// to the MAC the source's own neighbour table holds for Addr after a
// ping, which on ipvlan is the parent's (lab #21); every argument passes
// a parser before it reaches the shell.
func (h host) sendForceRenew(ctx context.Context, r Runner, script []byte, p ForceRenewParams) (string, error) {
	if err := h.needPortable("forcerenew"); err != nil {
		return "", err
	}
	switch p.Mode {
	case "unsigned", "badkey", "signed":
	default:
		return "", fmt.Errorf("forcerenew: unknown mode %q", p.Mode)
	}
	addr, err := validateAddr(p.Addr)
	if err != nil {
		return "", err
	}
	server, err := validateAddr(p.Server)
	if err != nil {
		return "", err
	}
	chaddr, err := validateMAC(p.CHAddr)
	if err != nil {
		return "", err
	}
	args := fmt.Sprintf("--iface %s --dst-ip %s --src-ip %s --chaddr %s --mode %s", h.nic, addr, server, chaddr, p.Mode)
	if p.ClientID != "" {
		id, err := validateClientID(p.ClientID)
		if err != nil {
			return "", err
		}
		args += " --client-id " + hexPlain(id)
	}
	if p.Mode != "unsigned" {
		if len(p.Nonce) != ForceRenewNonceLen {
			return "", fmt.Errorf("forcerenew: nonce is %d bytes, want %d", len(p.Nonce), ForceRenewNonceLen)
		}
		args += fmt.Sprintf(" --nonce %s --ack-replay %d", hex.EncodeToString(p.Nonce), p.AckReplay)
	}
	body := string(script)
	if body == "" || !strings.HasSuffix(body, "\n") || strings.Contains(body, "\nLABEOF\n") || strings.HasPrefix(body, "LABEOF\n") {
		return "", errors.New("forcerenew: the sender script is empty, lacks a final newline or holds the heredoc marker")
	}
	if err := reachable(ctx, r, addr); err != nil {
		return "", fmt.Errorf("forcerenew: %w", err)
	}
	neighOf := addr
	if p.Offlink {
		route, err := r.Run(ctx, "ip route get "+addr)
		if err != nil {
			return "", fmt.Errorf("forcerenew: ip route get %s: %w", addr, err)
		}
		v := routeViaRE.FindStringSubmatch(route)
		if v == nil {
			return "", fmt.Errorf("forcerenew: %s has no next hop on the source (%q), but this cell is behind a relay", addr, strings.TrimSpace(route))
		}
		if neighOf, err = validateAddr(v[1]); err != nil {
			return "", err
		}
	}
	neigh, err := r.Run(ctx, fmt.Sprintf("ip neigh show %s dev %s", neighOf, h.nic))
	if err != nil {
		return "", fmt.Errorf("forcerenew: read the neighbour entry for %s: %w", neighOf, err)
	}
	m := neighMACRE.FindStringSubmatch(strings.ToLower(neigh))
	if m == nil {
		return "", fmt.Errorf("forcerenew: no neighbour MAC for %s on %s: %q", neighOf, h.nic, strings.TrimSpace(neigh))
	}
	if _, err := r.Run(ctx, fmt.Sprintf("sudo mkdir -p /run/lab && sudo tee %s >/dev/null <<'LABEOF'\n%sLABEOF\n", forceRenewScriptPath, body)); err != nil {
		return "", fmt.Errorf("forcerenew: write the sender to %s: %w", forceRenewScriptPath, err)
	}
	out, err := r.Run(ctx, fmt.Sprintf("sudo python3 %s --dst-mac %s %s", forceRenewScriptPath, m[1], args))
	if err != nil {
		return "", fmt.Errorf("forcerenew: run the sender (%s): %w", p.Mode, err)
	}
	return strings.TrimSpace(out), nil
}

func (a *DnsmasqAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return a.host().sendForceRenew(ctx, a.Runner, script, p)
}

func (a *KeaAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return a.host().sendForceRenew(ctx, a.Runner, script, p)
}

func (a *ISCDHCPAdapter) SendForceRenew(ctx context.Context, script []byte, p ForceRenewParams) (string, error) {
	return a.host().sendForceRenew(ctx, a.Runner, script, p)
}
