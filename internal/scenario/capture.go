package scenario

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// DHCPMsg is one DHCPv4 message from the cell's capture, as
// scripts/dhcp-exchange-check.sh's dhcp_message_log prints it. Fields
// the message does not carry are empty.
type DHCPMsg struct {
	At        time.Time
	Type      string // DISCOVER, OFFER, REQUEST, ACK, NAK, DECLINE, RELEASE, INFORM
	XID       string
	CHAddr    string
	ClientID  string // option 61, colon hex
	Server    string // option 54
	Requested string // option 50
	CIAddr    string
	YIAddr    string
	Src       string
	Dst       string
	Secs      int           // BOOTP secs, recorded unjudged (lab #12, RFC 2131 Table 5)
	LeaseTime time.Duration // option 51, zero when absent
}

// CaptureReader reads the messages the observer has captured so far for
// one identity (a MAC or an option 61 value in colon hex) and keeps the
// snapshot it read at snapshotPath. Group C judges what went over the
// wire while the scenario runs; the cell's PCAP only exists after
// capture-stop (#23 defeat A1).
type CaptureReader interface {
	Messages(ctx context.Context, ident, snapshotPath string) ([]DHCPMsg, error)
}

// ObserverCapture snapshots the live capture out of the cell's observer
// container (scripts/capture-start.sh writes it with tcpdump -U) and
// decodes it with the repo's own dhcp_message_log, so Go never carries
// a second DHCP decoder.
type ObserverCapture struct {
	Cell     string
	RepoRoot string
}

func (o ObserverCapture) Messages(ctx context.Context, ident, snapshotPath string) ([]DHCPMsg, error) {
	if err := o.snapshot(ctx, snapshotPath); err != nil {
		return nil, err
	}
	return decodeCapture(ctx, o.RepoRoot, snapshotPath, ident)
}

// decodeCapture runs dhcp_message_log over pcap for ident, asking for
// option 51 so the C5 family times T1/T2 from the bound ACK (lab #12).
func decodeCapture(ctx context.Context, repoRoot, pcap, ident string) ([]DHCPMsg, error) {
	script := repoRoot + "/scripts/dhcp-exchange-check.sh"
	cmd := exec.CommandContext(ctx, "bash", "-c", `. "$1"; dhcp_message_log "$2" "$3" 51`,
		"dhcp-message-log-wrapper", script, pcap, ident)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dhcp_message_log: %w", err)
	}
	return parseMessageLog(string(out))
}

// snapshot copies the live capture out of the observer to path.
func (o ObserverCapture) snapshot(ctx context.Context, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("capture snapshot: %w", err)
	}
	cp := exec.CommandContext(ctx, "sudo", "-n", "docker", "exec", "lab-observer-"+o.Cell, "cat", "/tmp/obs.pcap")
	cp.Stdout = f
	runErr := cp.Run()
	closeErr := f.Close()
	if runErr != nil {
		return fmt.Errorf("capture snapshot from lab-observer-%s: %w", o.Cell, runErr)
	}
	if closeErr != nil {
		return fmt.Errorf("capture snapshot: %w", closeErr)
	}
	return nil
}

// parseMessageLog reads dhcp_message_log's lines: ts TYPE xid chaddr cid
// server requested ciaddr yiaddr src dst secs opt51, "-" for an absent field.
func parseMessageLog(out string) ([]DHCPMsg, error) {
	var msgs []DHCPMsg
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 13 {
			return nil, fmt.Errorf("dhcp_message_log line has %d fields, want 13: %q", len(f), line)
		}
		ts, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return nil, fmt.Errorf("dhcp_message_log timestamp %q: %w", f[0], err)
		}
		for i := range f {
			if f[i] == "-" {
				f[i] = ""
			}
		}
		secs, err := strconv.Atoi(f[11])
		if err != nil || secs < 0 || secs > 65535 {
			return nil, fmt.Errorf("dhcp_message_log secs %q is not 0-65535", f[11])
		}
		var lease time.Duration
		if f[12] != "" {
			hex, ok := strings.CutPrefix(f[12], "0x")
			v, err := strconv.ParseUint(hex, 16, 32)
			if !ok || len(hex) != 8 || err != nil {
				return nil, fmt.Errorf("dhcp_message_log option 51 %q is not 4 bytes of hex", f[12])
			}
			lease = time.Duration(v) * time.Second
		}
		sec := int64(ts)
		msgs = append(msgs, DHCPMsg{
			Secs: secs, LeaseTime: lease,
			At:   time.Unix(sec, int64((ts-float64(sec))*1e9)),
			Type: f[1], XID: f[2], CHAddr: f[3], ClientID: f[4], Server: f[5],
			Requested: f[6], CIAddr: f[7], YIAddr: f[8], Src: f[9], Dst: f[10],
		})
	}
	return msgs, nil
}

// writeMessageLog keeps the decoded messages beside the snapshot, so a
// verdict's evidence is readable without tcpdump.
func writeMessageLog(path string, msgs []DHCPMsg) error {
	var b strings.Builder
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	for _, m := range msgs {
		lease := "-"
		if m.LeaseTime > 0 {
			lease = m.LeaseTime.String()
		}
		fmt.Fprintf(&b, "%s %s %s %s %s %s %s %s %s %s %s secs=%d lease=%s\n",
			m.At.UTC().Format("15:04:05.000"), m.Type, dash(m.XID), dash(m.CHAddr), dash(m.ClientID),
			dash(m.Server), dash(m.Requested), dash(m.CIAddr), dash(m.YIAddr), dash(m.Src), dash(m.Dst), m.Secs, lease)
	}
	if len(msgs) == 0 {
		b.WriteString("no DHCP message for this identity in the capture\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// messagesOfType keeps the messages of one type.
func messagesOfType(msgs []DHCPMsg, typ string) []DHCPMsg {
	var out []DHCPMsg
	for _, m := range msgs {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return out
}

// messagesBetween keeps the messages with from <= At <= to.
func messagesBetween(msgs []DHCPMsg, from, to time.Time) []DHCPMsg {
	var out []DHCPMsg
	for _, m := range msgs {
		if !m.At.Before(from) && !m.At.After(to) {
			out = append(out, m)
		}
	}
	return out
}

// messagesAfter keeps the messages with At >= from.
func messagesAfter(msgs []DHCPMsg, from time.Time) []DHCPMsg {
	var out []DHCPMsg
	for _, m := range msgs {
		if !m.At.Before(from) {
			out = append(out, m)
		}
	}
	return out
}
