package sourceadapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// haMarker ends every line the kea-ha template adds to the kea template.
const haMarker = " # lab-ha"

// haTemplateDrift strips the marked lines and reports the first line
// where what is left differs from the base template, or "" when equal.
func haTemplateDrift(base, ha string) string {
	var kept []string
	for _, l := range strings.Split(ha, "\n") {
		if !strings.HasSuffix(l, haMarker) {
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
			return fmt.Sprintf("line %d: kea %q, kea-ha %q", i+1, x, y)
		}
	}
	return ""
}

func readTemplate(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Defeat 5 (lab #12): the HA template is the kea template plus marked
// lines, so every adapter regex anchors on both alike.
func TestKeaHATemplateIsKeaPlusMarkedLines(t *testing.T) {
	base, ha := readTemplate(t, "kea-user-data.tmpl.yaml"), readTemplate(t, "kea-ha-user-data.tmpl.yaml")
	if d := haTemplateDrift(base, ha); d != "" {
		t.Fatalf("kea-ha template drifted from kea: %s", d)
	}
	cfg := baselineConfig(t, "kea-ha-user-data.tmpl.yaml", "/etc/kea/kea-dhcp4.conf")
	for _, want := range []string{
		`libdhcp_ha.so`, `"this-server-name": "primary"`, `"mode": "hot-standby"`,
		`"heartbeat-delay": 2000`, `"max-response-delay": 6000`, `"max-unacked-clients": 0`,
		`"enable-multi-threading": true`, `"http-dedicated-listener": true`,
		`{ "name": "primary", "url": "http://10.200.1.2:8001/", "role": "primary"`,
		`{ "name": "partner", "url": "http://10.200.1.3:8001/", "role": "standby"`,
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered kea-ha config lacks %s", want)
		}
	}
	if strings.Count(cfg, `"http-port": 8000`) != 0 || !strings.Contains(ha, `"http-host": "127.0.0.1"`) {
		t.Error("the control agent moved off 127.0.0.1:8000 or into the dhcp4 config")
	}
}

// The drift check itself fails on a template with valid-lifetime moved.
func TestKeaHATemplateDriftCatchesAMovedAnchor(t *testing.T) {
	base, ha := readTemplate(t, "kea-user-data.tmpl.yaml"), readTemplate(t, "kea-ha-user-data.tmpl.yaml")
	line := `      "valid-lifetime": 3600,`
	if !strings.Contains(ha, line+"\n") {
		t.Fatalf("fixture lost %q", line)
	}
	moved := strings.Replace(ha, line+"\n", "", 1)
	moved = strings.Replace(moved, `      "hooks-libraries": [`, `      "hooks-libraries": [`+"\n"+line, 1)
	if haTemplateDrift(base, moved) == "" {
		t.Fatal("a moved valid-lifetime line passed the drift check")
	}
	if haTemplateDrift(base, strings.Replace(ha, `"valid-lifetime": 3600, `, `"valid-lifetime": 3600,`, 1)+"x") == "" {
		t.Fatal("trailing text passed the drift check")
	}
}

// Each Kea edit regex matches the HA config as often as the kea config.
func TestKeaRegexesAnchorOnTheHAConfig(t *testing.T) {
	base := baselineConfig(t, "kea-user-data.tmpl.yaml", "/etc/kea/kea-dhcp4.conf")
	ha := baselineConfig(t, "kea-ha-user-data.tmpl.yaml", "/etc/kea/kea-dhcp4.conf")
	for name, re := range map[string]interface{ FindAllStringIndex(string, int) [][]int }{
		"valid-lifetime": keaValidLifetimeRE, "routers": keaRoutersOptionRE, "classes": keaClassesRE,
		"not-b5": keaNotB5RE, "class pool": keaClassPoolRE, "lease_cmds hook": keaLeaseCmdsHookRE,
		"main pool": keaMainPoolRE,
	} {
		nb, nh := len(re.FindAllStringIndex(base, -1)), len(re.FindAllStringIndex(ha, -1))
		if nb != 1 || nh != 1 {
			t.Errorf("%s: kea %d matches, kea-ha %d, want 1 and 1", name, nb, nh)
		}
	}
}

// ShortenLeaseTime and SetDNSOption keep the HA block on a pair peer.
func TestKeaHAEditsKeepTheHABlock(t *testing.T) {
	ctx := context.Background()
	r := baselineRunner(t, "kea-ha")
	a := &KeaAdapter{Runner: r}
	if _, err := a.ShortenLeaseTime(ctx, 60); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, `"valid-lifetime": 60,`) || !strings.Contains(r.cfg, "libdhcp_ha.so") {
		t.Fatalf("shortened config lost a part:\n%s", r.cfg)
	}
	r = baselineRunner(t, "kea-ha")
	if _, err := (&KeaAdapter{Runner: r}).SetDNSOption(ctx, "10.200.1.253"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, "10.200.1.253") || !strings.Contains(r.cfg, "libdhcp_ha.so") {
		t.Fatalf("DNS option config lost a part:\n%s", r.cfg)
	}
	r = baselineRunner(t, "kea-ha")
	if _, err := (&KeaAdapter{Runner: r}).NarrowPool(ctx, "10.200.1.100", "10.200.1.101"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.cfg, `"pool": "10.200.1.100 - 10.200.1.101"`) || !strings.Contains(r.cfg, "libdhcp_ha.so") {
		t.Fatalf("narrowed config lost a part:\n%s", r.cfg)
	}
}

// Option A of lab #12: the standby's VM stops the v6 daemons the kea
// template enables, after that enable, so only the primary serves v6.
func TestKeaHAStandbyStopsTheV6Daemons(t *testing.T) {
	ha := readTemplate(t, "kea-ha-user-data.tmpl.yaml")
	lines := strings.Split(ha, "\n")
	enable, stop := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "systemctl enable") && strings.Contains(l, "kea-dhcp6-server") {
			enable = i
		}
		if strings.HasSuffix(l, haMarker) && strings.Contains(l, `[ "__HA_THIS__" = primary ] ||`) &&
			strings.Contains(l, "systemctl disable --now kea-dhcp6-server radvd") {
			if stop >= 0 {
				t.Fatal("two standby stop lines")
			}
			stop = i
		}
	}
	if enable < 0 || stop < 0 || stop < enable {
		t.Fatalf("enable line %d, standby stop line %d: want the stop after the enable", enable, stop)
	}
	for _, l := range lines[stop+1:] {
		if strings.Contains(l, "kea-dhcp6-server") || strings.Contains(l, "radvd") {
			t.Fatalf("a later line starts the v6 side again: %q", l)
		}
	}
}
