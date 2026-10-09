package scenario

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Group F (#20) reads option bytes off the wire. tcpdump prints option 80
// as SLP-NA and 77, 108 and message type 9 as Unknown, so the bytes come
// from dhcp_option_bytes, which keys on the option code.

// OptMsg is one DHCPv4 message with the option bytes asked for. A code
// present in Opts is on the message (an empty slice is a zero-length
// option such as 80); a missing code is not.
type OptMsg struct {
	At   time.Time
	Type string
	XID  string
	Opts map[int][]byte
}

// Has reports whether the message carries option code.
func (m OptMsg) Has(code int) bool { _, ok := m.Opts[code]; return ok }

// OptionReader is the capture reader's option-bytes view (group F, #20).
// A CaptureReader that cannot offer it leaves a group F scenario BLOCKED.
type OptionReader interface {
	Options(ctx context.Context, ident, snapshotPath string, codes []int) ([]OptMsg, error)
}

// Options snapshots the live capture and decodes the codes with the
// repo's own dhcp_option_bytes.
func (o ObserverCapture) Options(ctx context.Context, ident, snapshotPath string, codes []int) ([]OptMsg, error) {
	if err := o.snapshot(ctx, snapshotPath); err != nil {
		return nil, err
	}
	list := make([]string, len(codes))
	for i, c := range codes {
		list[i] = strconv.Itoa(c)
	}
	script := o.RepoRoot + "/scripts/dhcp-exchange-check.sh"
	cmd := exec.CommandContext(ctx, "bash", "-c", `. "$1"; dhcp_option_bytes "$2" "$3" "$4"`,
		"dhcp-option-bytes-wrapper", script, snapshotPath, ident, strings.Join(list, ","))
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dhcp_option_bytes: %w", err)
	}
	return parseOptionBytes(string(out), codes)
}

// parseOptionBytes reads dhcp_option_bytes' lines: ts TYPE xid, then one
// field per code, "-" for absent, "0x<hex>" for present.
func parseOptionBytes(out string, codes []int) ([]OptMsg, error) {
	var msgs []OptMsg
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3+len(codes) {
			return nil, fmt.Errorf("dhcp_option_bytes line has %d fields, want %d: %q", len(f), 3+len(codes), line)
		}
		ts, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			return nil, fmt.Errorf("dhcp_option_bytes timestamp %q: %w", f[0], err)
		}
		m := OptMsg{Type: f[1], XID: f[2], Opts: map[int][]byte{}}
		sec := int64(ts)
		m.At = time.Unix(sec, int64((ts-float64(sec))*1e9))
		for i, c := range codes {
			v := f[3+i]
			if v == "-" {
				continue
			}
			if !strings.HasPrefix(v, "0x") {
				return nil, fmt.Errorf("dhcp_option_bytes value %q for option %d is neither - nor 0x<hex>", v, c)
			}
			b, err := hex.DecodeString(v[2:])
			if err != nil {
				return nil, fmt.Errorf("dhcp_option_bytes value %q for option %d: %w", v, c, err)
			}
			m.Opts[c] = b
		}
		msgs = append(msgs, m)
	}
	return msgs, nil
}

// writeOptLog keeps the decoded option bytes beside the snapshot.
func writeOptLog(path string, msgs []OptMsg) error {
	var b strings.Builder
	for _, m := range msgs {
		codes := make([]int, 0, len(m.Opts))
		for c := range m.Opts {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		fmt.Fprintf(&b, "%s %s %s", m.At.UTC().Format("15:04:05.000"), m.Type, m.XID)
		for _, c := range codes {
			fmt.Fprintf(&b, " %d=0x%x", c, m.Opts[c])
		}
		b.WriteString("\n")
	}
	if len(msgs) == 0 {
		b.WriteString("no DHCP message for this identity in the capture\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

var tagVersionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$`)

// clientHasFeature reports whether the plugin in tag already carries a
// feature added in release since ("2.4.0"). A release candidate of that
// version counts as present (-rcN is part of the same version). An
// unparsable tag is an error, never a guess: the verdict then BLOCKS.
func clientHasFeature(tag string, since [3]int) (bool, error) {
	v := tag
	if i := strings.LastIndex(v, ":"); i >= 0 {
		v = v[i+1:]
	}
	m := tagVersionRE.FindStringSubmatch(v)
	if m == nil {
		return false, fmt.Errorf("plugin tag %q is not a vX.Y.Z release or release candidate, so the lab cannot tell which client features it carries", tag)
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return false, fmt.Errorf("plugin tag %q: %w", tag, err)
		}
		if n != since[i] {
			return n > since[i], nil
		}
	}
	return true, nil
}

// fSince4 is the release that gave the client user_class (F1) and
// rapid_commit (F3) (docker-net-dhcp v2.4.0).
var fSince4 = [3]int{2, 4, 0}
