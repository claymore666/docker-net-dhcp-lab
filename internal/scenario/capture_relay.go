package scenario

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RelayMsg is one DHCPv4 message from a relay cell's capture, as
// dhcp_relay_log prints it: DHCPMsg plus what only a relay changes
// (lab #11, RFC 3046). LeaseTime is not decoded here.
type RelayMsg struct {
	DHCPMsg
	GIAddr string // relay agent address, empty for 0.0.0.0
	Flags  string // "0x%04x", broadcast bit 0x8000 (RFC 2131 section 2)
	EthSrc string
	EthDst string
	Opt82  string // option 82 value, "0x" hex, empty when absent
}

// RelayReader is a CaptureReader that also decodes the relay fields; the
// observer on either segment of a relay cell implements both (#11).
type RelayReader interface {
	RelayMessages(ctx context.Context, ident, snapshotPath string) ([]RelayMsg, error)
}

// RelayMessages snapshots the live capture and decodes it with the
// repo's dhcp_relay_log, the way Messages does with dhcp_message_log.
func (o ObserverCapture) RelayMessages(ctx context.Context, ident, snapshotPath string) ([]RelayMsg, error) {
	if err := o.snapshot(ctx, snapshotPath); err != nil {
		return nil, err
	}
	return decodeRelayCapture(ctx, o.RepoRoot, snapshotPath, ident)
}

// decodeRelayCapture runs the repo's dhcp_relay_log over a pcap file.
func decodeRelayCapture(ctx context.Context, repoRoot, pcap, ident string) ([]RelayMsg, error) {
	script := repoRoot + "/scripts/dhcp-exchange-check.sh"
	cmd := exec.CommandContext(ctx, "bash", "-c", `. "$1"; dhcp_relay_log "$2" "$3"`,
		"dhcp-relay-log-wrapper", script, pcap, ident)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dhcp_relay_log: %w", err)
	}
	return parseRelayLog(string(out))
}

// parseRelayLog reads dhcp_relay_log's lines: the 12 fields of
// dhcp_message_log, then giaddr flags ethsrc ethdst o82; "-" is absent.
func parseRelayLog(out string) ([]RelayMsg, error) {
	var msgs []RelayMsg
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 17 {
			return nil, fmt.Errorf("dhcp_relay_log line has %d fields, want 17: %q", len(f), line)
		}
		ts, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return nil, fmt.Errorf("dhcp_relay_log timestamp %q: %w", f[0], err)
		}
		for i := range f {
			if f[i] == "-" {
				f[i] = ""
			}
		}
		secs, err := strconv.Atoi(f[11])
		if err != nil || secs < 0 || secs > 65535 {
			return nil, fmt.Errorf("dhcp_relay_log secs %q is not 0-65535", f[11])
		}
		if f[13] == "" || !strings.HasPrefix(f[13], "0x") {
			return nil, fmt.Errorf("dhcp_relay_log flags %q is not hex", f[13])
		}
		sec := int64(ts)
		msgs = append(msgs, RelayMsg{
			DHCPMsg: DHCPMsg{
				Secs: secs,
				At:   time.Unix(sec, int64((ts-float64(sec))*1e9)),
				Type: f[1], XID: f[2], CHAddr: f[3], ClientID: f[4], Server: f[5],
				Requested: f[6], CIAddr: f[7], YIAddr: f[8], Src: f[9], Dst: f[10],
			},
			GIAddr: f[12], Flags: f[13], EthSrc: f[14], EthDst: f[15], Opt82: f[16],
		})
	}
	return msgs, nil
}

// writeRelayLog keeps the decoded relay messages beside the snapshot, as
// writeMessageLog does for the plain log (#11).
func writeRelayLog(path string, msgs []RelayMsg) error {
	var b strings.Builder
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, m := range msgs {
		fmt.Fprintf(&b, "%s %s %s %s src=%s dst=%s ci=%s yi=%s server=%s giaddr=%s flags=%s eth=%s>%s o82=%s\n",
			m.At.UTC().Format("15:04:05.000000"), m.Type, m.XID, dash(m.CHAddr), dash(m.Src), dash(m.Dst),
			dash(m.CIAddr), dash(m.YIAddr), dash(m.Server), dash(m.GIAddr), m.Flags,
			dash(m.EthSrc), dash(m.EthDst), dash(m.Opt82))
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// opt82Subs splits an option 82 value ("0x" hex) into its ordered
// (code, value hex) sub-options. A TLV that runs past the end, an empty
// option and a non-hex value are errors, never an empty list.
func opt82Subs(v string) ([][2]string, error) {
	h, ok := strings.CutPrefix(v, "0x")
	if !ok || h == "" {
		return nil, fmt.Errorf("option 82 %q is absent or empty", v)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("option 82 %q is not hex: %w", v, err)
	}
	var subs [][2]string
	for i := 0; i < len(b); {
		if i+2 > len(b) || i+2+int(b[i+1]) > len(b) {
			return nil, fmt.Errorf("option 82 %q: sub-option at byte %d runs past the end", v, i)
		}
		n := int(b[i+1])
		subs = append(subs, [2]string{strconv.Itoa(int(b[i])), hex.EncodeToString(b[i+2 : i+2+n])})
		i += 2 + n
	}
	return subs, nil
}

// opt82Echoed reports whether reply carries exactly request's relay
// agent information, sub-option for sub-option and in the same order
// (RFC 3046 section 2.2: the server copies it unchanged). A malformed or
// empty option on either side is an error, not "different".
func opt82Echoed(request, reply string) (bool, error) {
	a, err := opt82Subs(request)
	if err != nil {
		return false, fmt.Errorf("request: %w", err)
	}
	b, err := opt82Subs(reply)
	if err != nil {
		return false, fmt.Errorf("reply: %w", err)
	}
	if len(a) != len(b) {
		return false, nil
	}
	for i := range a {
		if a[i] != b[i] {
			return false, nil
		}
	}
	return true, nil
}
