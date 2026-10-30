package scenario

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

type evidenceDirKey struct{}

// WithEvidenceDir hands NetworkUp the shape's evidence directory, so a
// bridge that does not come up leaves the host's link and networkd state
// there (#138).
func WithEvidenceDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, evidenceDirKey{}, dir)
}

func evidenceDirFrom(ctx context.Context) string {
	dir, _ := ctx.Value(evidenceDirKey{}).(string)
	return dir
}

// bridgeCaptureBound caps the whole capture, so a host that has stopped
// answering cannot hold up the abort it is explaining (#138).
var bridgeCaptureBound = 45 * time.Second

// captureBridgeState records, best effort, what the host looked like when
// the bridge did not come up: links, networkd's view of the bridge and the
// segment NIC, and the networkd journal tail. It returns the file name, or
// "" when nothing was written; no failure here changes the abort (#138).
// The cause of the run-5 dnsmasq bridge-ipam abort was never measured
// because none of this was captured.
func captureBridgeState(ctx context.Context, r sourceadapter.Runner, dir, cell string, shape Shape, br string, failed []string) string {
	if dir == "" || ctx.Err() != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, bridgeCaptureBound)
	defer cancel()
	var b strings.Builder
	fmt.Fprintf(&b, "bridge %s of %s/%s did not come up\nfailed: %s\n", br, cell, shape, strings.Join(failed, "; "))
	for _, cmd := range []string{
		"ip -d link show",
		fmt.Sprintf("networkctl status --no-pager %s %s", br, SegmentNIC),
		"sudo journalctl -u systemd-networkd -n 80 --no-pager",
	} {
		out, err := r.Run(cctx, cmd)
		fmt.Fprintf(&b, "\n$ %s\n%s", cmd, out)
		if err != nil {
			fmt.Fprintf(&b, "(command failed: %v)\n", err)
		}
	}
	name := fmt.Sprintf("%s-%s-bridge-not-ready.txt", cell, shape)
	if os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o644) != nil {
		return ""
	}
	return name
}
