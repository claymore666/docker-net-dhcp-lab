package sourceadapter

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// foMarker ends every line the isc-failover template adds to the
// isc-dhcp template (lab #12).
const foMarker = " # lab-fo"

// foTemplateDrift strips the marked lines and reports the first line
// where what is left differs from the base template, or "".
func foTemplateDrift(base, fo string) string {
	var kept []string
	for _, l := range strings.Split(fo, "\n") {
		if !strings.HasSuffix(l, foMarker) {
			kept = append(kept, l)
		}
	}
	b := strings.Split(base, "\n")
	for i := 0; i < len(b) || i < len(kept); i++ {
		var x, y string
		if i < len(b) {
			x = b[i]
		}
		if i < len(kept) {
			y = kept[i]
		}
		if x != y {
			return fmt.Sprintf("line %d: base %q / failover %q", i+1, x, y)
		}
	}
	return ""
}

// Defeat 5 (lab #12): the failover template is the isc-dhcp template
// plus marked lines, so every adapter regex anchors on both alike.
func TestISCFailoverTemplateIsISCPlusMarkedLines(t *testing.T) {
	base, fo := readTemplate(t, "isc-dhcp-user-data.tmpl.yaml"), readTemplate(t, "isc-dhcp-failover-user-data.tmpl.yaml")
	if d := foTemplateDrift(base, fo); d != "" {
		t.Fatalf("isc-failover template drifted from isc-dhcp: %s", d)
	}
}

func TestISCFailoverDriftCheckCatchesAChange(t *testing.T) {
	base, fo := readTemplate(t, "isc-dhcp-user-data.tmpl.yaml"), readTemplate(t, "isc-dhcp-failover-user-data.tmpl.yaml")
	if foTemplateDrift(base, strings.Replace(fo, "default-lease-time", "default-lease-timX", 1)) == "" {
		t.Fatal("an edited unmarked line passed the drift check")
	}
	if foTemplateDrift(base, fo+"extra\n") == "" {
		t.Fatal("trailing text passed the drift check")
	}
}

// The primary's rendering carries the whole failover block, with mclt
// and split; the secondary's mclt and split are the template's
// commented-out tokens (dhcpd -t refuses them there, measured).
func TestISCFailoverRenderedBlock(t *testing.T) {
	cfg := baselineConfig(t, "isc-dhcp-failover-user-data.tmpl.yaml", "/etc/dhcp/dhcpd.conf")
	for _, want := range []string{
		`omapi-port 7911;`, `failover peer "lab" {`, "primary;", "address 10.200.1.2;", "peer address 10.200.1.3;",
		"port 647;", "peer port 647;", "max-response-delay 30;", "max-unacked-updates 10;",
		"load balance max seconds 3;", "mclt 60;", "split 128;",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered primary config lacks %q", want)
		}
	}
	if n := strings.Count(cfg, "failover peer \"lab\";"); n != 2 {
		t.Errorf("%d pools carry failover peer \"lab\";, want 2 (main and b5)", n)
	}
	raw := readTemplate(t, "isc-dhcp-failover-user-data.tmpl.yaml")
	for _, tok := range []string{"__FO_PRIMARY_ONLY__mclt 60;", "__FO_PRIMARY_ONLY__split 128;"} {
		if strings.Count(raw, tok) != 1 {
			t.Errorf("template lacks exactly one %q", tok)
		}
	}
	if !strings.Contains(raw, "__FO_ROLE__;") || !strings.Contains(raw, "address __FO_OWN_SEG__;") || !strings.Contains(raw, "peer address __FO_PEER_SEG__;") {
		t.Error("template lost a role or address token")
	}
}

// Each ISC edit regex matches the failover config as often as isc-dhcp's.
func TestISCRegexesAnchorOnTheFailoverConfig(t *testing.T) {
	base := baselineConfig(t, "isc-dhcp-user-data.tmpl.yaml", "/etc/dhcp/dhcpd.conf")
	fo := baselineConfig(t, "isc-dhcp-failover-user-data.tmpl.yaml", "/etc/dhcp/dhcpd.conf")
	for name, re := range map[string]interface{ FindAllStringIndex(string, int) [][]int }{
		"main range": iscMainRangeRE, "main pool deny": iscMainPoolDenyRE, "subnet": iscSubnetRE, "routers": iscRoutersLineRE,
	} {
		nb, nf := len(re.FindAllStringIndex(base, -1)), len(re.FindAllStringIndex(fo, -1))
		if nb != 1 || nf != 1 {
			t.Errorf("%s: isc-dhcp %d matches, isc-failover %d, want 1 and 1", name, nb, nf)
		}
	}
}

// The edits keep the failover block, and the user-class pool a Failover
// adapter adds is a failover pool too: a pool without the line would
// leave the class pool unreplicated and double-served.
func TestISCFailoverEditsKeepTheBlockAndPoolLine(t *testing.T) {
	ctx := context.Background()
	r := baselineRunner(t, "isc-failover")
	a := &ISCDHCPAdapter{Runner: r, Failover: true}
	uc := FeatureParams{Class: "lab-uc-f1", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}
	if _, err := a.EnableFeature(ctx, FeatureUserClassPool, uc); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(r.cfg, "failover peer \"lab\";"); n != 3 {
		t.Errorf("%d failover pool lines after the user-class pool, want 3\n%s", n, r.cfg)
	}
	if !strings.Contains(r.cfg, `failover peer "lab" {`) {
		t.Error("the user-class pool lost the failover block")
	}
	pool := r.cfg[strings.Index(r.cfg, `allow members of "f1"`)-80:]
	if !strings.Contains(pool[:strings.Index(pool, `range 10.200.1.203`)], `failover peer "lab";`) {
		t.Errorf("the f1 pool has no failover line:\n%s", pool)
	}
	plain := baselineRunner(t, "isc-dhcp")
	if _, err := (&ISCDHCPAdapter{Runner: plain}).EnableFeature(ctx, FeatureUserClassPool, uc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.cfg, "failover") {
		t.Error("a plain isc-dhcp adapter added a failover line")
	}
	r = baselineRunner(t, "isc-failover")
	if _, err := (&ISCDHCPAdapter{Runner: r, Failover: true}).ShortenLeaseTime(ctx, 60); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, `failover peer "lab" {`) || !strings.Contains(r.cfg, "default-lease-time 60;") {
		t.Errorf("shortened config lost a part:\n%s", r.cfg)
	}
}

// The secondary serves no v6 and no RA: both lines are marked and
// guarded by the role token (Option A of lab #12), after the enables.
func TestISCFailoverSecondaryStopsV6(t *testing.T) {
	fo := readTemplate(t, "isc-dhcp-failover-user-data.tmpl.yaml")
	var sed, radvd bool
	for _, l := range strings.Split(fo, "\n") {
		if !strings.HasSuffix(l, foMarker) || !strings.Contains(l, `[ "__HA_THIS__" = primary ] ||`) {
			continue
		}
		sed = sed || strings.Contains(l, `INTERFACESv6=\"\"`)
		radvd = radvd || strings.Contains(l, "systemctl disable --now radvd")
	}
	if !sed || !radvd {
		t.Errorf("secondary v6 stop lines: INTERFACESv6 %v, radvd %v", sed, radvd)
	}
}
