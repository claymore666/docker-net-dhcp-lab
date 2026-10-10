package sourceadapter

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// baselineConfig renders the config block cloud-init/<name> writes to the
// source VM, so the tests run the adapters against the real baseline and
// a template change that moves an anchor fails here (#20).
// baselineConfig renders the heredoc the template writes to path.
func baselineConfig(t *testing.T, tmpl, path string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "cloud-init", tmpl))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "cat >"+path+" <<'")
	if !ok {
		t.Fatalf("%s: no heredoc writes %s", tmpl, path)
	}
	delim, after, _ := strings.Cut(after, "'\n")
	body, _, _ := strings.Cut(after, "\n    "+delim+"\n")
	var out []string
	for _, l := range strings.Split(body, "\n") {
		out = append(out, strings.TrimPrefix(l, "    "))
	}
	cfg := strings.Join(out, "\n") + "\n"
	for k, v := range map[string]string{
		"__SEG_SUBNET__": "10.200.1.0/24", "__SEG_NETWORK__": "10.200.1.0", "__SEG_NETMASK__": "255.255.255.0",
		"__SEG_GATEWAY__": "10.200.1.1", "__POOL_START__": "10.200.1.100", "__POOL_END__": "10.200.1.200",
		"__CLASS_POOL_START__": "10.200.1.221", "__CLASS_POOL_END__": "10.200.1.230",
		"__SEG_SUBNET6__": "fd42:200:0:100::/64", "__POOL6_START__": "fd42:200:0:100::100",
		"__POOL6_END__": "fd42:200:0:100::1ff", "__TEMP6_POOL__": "fd42:200:0:100::200/120",
		"__HA_THIS__": "primary", "__HA_PRIMARY_SEG__": "10.200.1.2", "__HA_PARTNER_SEG__": "10.200.1.3",
	} {
		cfg = strings.ReplaceAll(cfg, k, v)
	}
	if strings.Contains(cfg, "__") {
		t.Fatalf("%s: unsubstituted placeholder left in\n%s", tmpl, cfg)
	}
	return cfg
}

var baselines = map[string]struct{ tmpl, path string }{
	"kea":      {"kea-user-data.tmpl.yaml", "/etc/kea/kea-dhcp4.conf"},
	"kea-ha":   {"kea-ha-user-data.tmpl.yaml", "/etc/kea/kea-dhcp4.conf"},
	"isc-dhcp": {"isc-dhcp-user-data.tmpl.yaml", "/etc/dhcp/dhcpd.conf"},
	"dnsmasq":  {"dnsmasq-user-data.tmpl.yaml", "/etc/dnsmasq.conf"},
	"pihole":   {"pihole-user-data.tmpl.yaml", "/etc/dnsmasq.d/90-lab.conf"},
}

// cfgRunner is a source whose config file the adapter reads and writes;
// failWrite and failRestart inject the two failures a restore must survive.
type cfgRunner struct {
	cfg                      string
	writes                   []string
	restarts                 int
	failWriteN, failRestartN int // fail the Nth call (1-based), 0 = never
	writeCalls, restartCalls int
}

func (c *cfgRunner) Run(_ context.Context, cmd string) (string, error) {
	switch {
	case strings.HasPrefix(cmd, "sudo cat "):
		return c.cfg, nil
	case strings.HasPrefix(cmd, "sudo tee "):
		c.writeCalls++
		if c.failWriteN == c.writeCalls {
			return "", errors.New("write failed")
		}
		body := cmd[strings.Index(cmd, "<<'LABEOF'\n")+len("<<'LABEOF'\n"):]
		c.cfg = strings.TrimSuffix(body, "LABEOF\n")
		c.writes = append(c.writes, c.cfg)
	case strings.Contains(cmd, "systemctl restart"):
		c.restartCalls++
		if c.failRestartN == c.restartCalls {
			return "", errors.New("restart failed")
		}
		c.restarts++
	}
	return "", nil
}

func featureAdapter(name string, r Runner) Adapter {
	if name == "pihole" {
		return &PiholeAdapter{Runner: r}
	}
	return groupBAdapters(r)[name]
}

func baselineRunner(t *testing.T, name string) *cfgRunner {
	b := baselines[name]
	return &cfgRunner{cfg: baselineConfig(t, b.tmpl, b.path)}
}

const f1ID = "00:6c:61:62:2d:66:32:62" // 0x00 type byte + "lab-f2b"

type featureCase struct {
	feature Feature
	params  FeatureParams
	cap     Capability
}

var featureCases = []featureCase{
	{FeatureUserClassPool, FeatureParams{Class: "lab-uc-f1", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}, CapUserClassPool},
	{FeatureOffer108, FeatureParams{Seconds: 1800}, CapOption108},
	{FeatureForce108, FeatureParams{Seconds: 1800, ClientID: f1ID}, CapOption108},
	{FeatureRapidCommit4, FeatureParams{}, CapRapidCommit4},
	{FeatureForceRenewNonce, FeatureParams{ClientID: f1ID, Nonce: katNonce}, CapForceRenewNonce},
}

func hasCap(a Adapter, c Capability) bool {
	for _, x := range a.Capabilities() {
		if x == c {
			return true
		}
	}
	return false
}

// Each supported feature changes the config, restarts once, and restore
// writes the captured bytes back byte for byte (defeat 1).
func TestEnableFeatureChangesAndRestoresByteForByte(t *testing.T) {
	for name := range baselines {
		for _, c := range featureCases {
			a := featureAdapter(name, nil)
			if !hasCap(a, c.cap) {
				continue
			}
			t.Run(name+"/"+string(c.feature), func(t *testing.T) {
				r := baselineRunner(t, name)
				orig := r.cfg
				a := featureAdapter(name, r)
				restore, err := a.EnableFeature(context.Background(), c.feature, c.params)
				if err != nil {
					t.Fatal(err)
				}
				if r.cfg == orig || r.restarts != 1 {
					t.Fatalf("config changed=%v restarts=%d, want a change and one restart", r.cfg != orig, r.restarts)
				}
				if err := restore(context.Background()); err != nil {
					t.Fatal(err)
				}
				if r.cfg != orig || r.restarts != 2 {
					t.Fatalf("restore left %d restarts and config equal=%v", r.restarts, r.cfg == orig)
				}
			})
		}
	}
}

// A source that cannot do a feature does not declare the capability and
// refuses the call before touching anything.
func TestEnableFeatureRefusesWhatTheSourceCannotDo(t *testing.T) {
	for _, name := range []string{"kea", "isc-dhcp"} {
		r := baselineRunner(t, name)
		a := featureAdapter(name, r)
		if hasCap(a, CapRapidCommit4) {
			t.Errorf("%s declares CapRapidCommit4", name)
		}
		if _, err := a.EnableFeature(context.Background(), FeatureRapidCommit4, FeatureParams{}); err == nil {
			t.Errorf("%s accepted rapid commit", name)
		}
		if len(r.writes) != 0 {
			t.Errorf("%s wrote a config for a refused feature", name)
		}
	}
	r := baselineRunner(t, "kea")
	a := featureAdapter("kea", r)
	if hasCap(a, CapTemporary6) {
		t.Error("kea declares CapTemporary6; Kea 2.6.3 grants no IA_TA")
	}
	if _, err := a.EnableFeature(context.Background(), FeatureTemporary6, FeatureParams{}); err == nil || len(r.writes) != 0 {
		t.Errorf("kea accepted FeatureTemporary6 (err %v, %d writes)", err, len(r.writes))
	}
}

// A failed write or restart puts the config back before the error
// returns, and restore itself still restarts after a failed write.
func TestEnableFeatureRollsBackOnEveryFailurePath(t *testing.T) {
	ctx := context.Background()
	for name := range baselines {
		for _, mode := range []string{"write", "restart"} {
			r := baselineRunner(t, name)
			orig := r.cfg
			if mode == "write" {
				r.failWriteN = 1
			} else {
				r.failRestartN = 1
			}
			a := featureAdapter(name, r)
			restore, err := a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800})
			if err == nil || restore != nil {
				t.Fatalf("%s/%s: err=%v restore=%v, want an error and no restore", name, mode, err, restore != nil)
			}
			if r.cfg != orig {
				t.Errorf("%s/%s: failed enable left the changed config behind", name, mode)
			}
			if r.restarts < 1 {
				t.Errorf("%s/%s: rollback did not restart the source", name, mode)
			}
		}
		// restore: write fails, restart must still be tried.
		r := baselineRunner(t, name)
		a := featureAdapter(name, r)
		restore, err := a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800})
		if err != nil {
			t.Fatal(err)
		}
		before := r.restartCalls
		r.failWriteN = r.writeCalls + 1
		if err := restore(ctx); err == nil {
			t.Errorf("%s: restore with a failing write returned nil", name)
		}
		if r.restartCalls != before+1 {
			t.Errorf("%s: restore skipped the restart after a failed write", name)
		}
	}
}

// A config that already carries the feature, or lacks its anchor, is
// refused with nothing written (a stale F config would give wrong verdicts).
func TestEnableFeatureRefusesALeftoverAndAMissingAnchor(t *testing.T) {
	ctx := context.Background()
	for name := range baselines {
		r := baselineRunner(t, name)
		a := featureAdapter(name, r)
		if _, err := a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800}); err != nil {
			t.Fatal(err)
		}
		n := len(r.writes)
		if _, err := a.EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800}); err == nil || !strings.Contains(err.Error(), "already") {
			t.Errorf("%s: second enable = %v, want an already-carries refusal", name, err)
		}
		bare := &cfgRunner{cfg: "nothing to anchor on\n"}
		if _, err := featureAdapter(name, bare).EnableFeature(ctx, FeatureOffer108, FeatureParams{Seconds: 1800}); err == nil || !strings.Contains(err.Error(), "anchor") {
			t.Errorf("%s: missing anchor = %v, want an anchor refusal", name, err)
		}
		if len(r.writes) != n || len(bare.writes) != 0 {
			t.Errorf("%s: a refused call wrote a config", name)
		}
	}
}

// Parameters that reach a config are guarded before any ssh (defeat 17).
func TestEnableFeatureRejectsBadParametersBeforeAnySSH(t *testing.T) {
	bad := []struct {
		f Feature
		p FeatureParams
	}{
		{FeatureUserClassPool, FeatureParams{Class: `x"; rm -rf /`, PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}},
		{FeatureUserClassPool, FeatureParams{Class: "", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}},
		{FeatureUserClassPool, FeatureParams{Class: "ok", PoolStart: "10.200.1.210", PoolEnd: "10.200.1.203"}},
		{FeatureUserClassPool, FeatureParams{Class: "ok", PoolStart: "nope", PoolEnd: "10.200.1.203"}},
		{FeatureOffer108, FeatureParams{}},
		{FeatureForce108, FeatureParams{Seconds: 1, ClientID: "not-hex"}},
		{FeatureForce108, FeatureParams{Seconds: 1, ClientID: `00:aa'; id #`}},
		{FeatureForceRenewNonce, FeatureParams{ClientID: f1ID, Nonce: katNonce[:15]}},
		{FeatureForceRenewNonce, FeatureParams{ClientID: f1ID}},
		{FeatureForceRenewNonce, FeatureParams{ClientID: `00:aa" or true`, Nonce: katNonce}},
		{"bogus", FeatureParams{}},
	}
	for name := range baselines {
		for _, c := range bad {
			r := &fakeRunner{}
			if _, err := featureAdapter(name, r).EnableFeature(context.Background(), c.f, c.p); err == nil {
				t.Errorf("%s accepted %v %+v", name, c.f, c.p)
			}
			if len(r.calls) != 0 {
				t.Errorf("%s ran %v for a bad parameter", name, r.calls)
			}
		}
	}
}

func enabled(t *testing.T, name string, f Feature, p FeatureParams) string {
	t.Helper()
	r := baselineRunner(t, name)
	if _, err := featureAdapter(name, r).EnableFeature(context.Background(), f, p); err != nil {
		t.Fatalf("%s %s: %v", name, f, err)
	}
	return r.cfg
}

func mustContain(t *testing.T, label, cfg string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(cfg, w) {
			t.Errorf("%s: config lacks %q\n%s", label, w, cfg)
		}
	}
}

// The rendered snippets, per source: the user-class pool, the main
// pool kept away from the class (defeat 7, 14), the client-id guard on
// the forced option (defeat 2) and no tag on the offered one.
func TestRenderedSnippetsCarryTheirGuards(t *testing.T) {
	uc := FeatureParams{Class: "lab-uc-f1", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}
	// RFC 3004: one length byte (0x09) then "lab-uc-f1".
	const classHex = "096c61622d75632d6631"
	mustContain(t, "kea f1", enabled(t, "kea", FeatureUserClassPool, uc),
		`"test": "option[77].hex == 0x`+classHex+`"`,
		`not member('b5') and not member('f1')`,
		`{ "pool": "10.200.1.203 - 10.200.1.210", "client-class": "f1" }`)
	mustContain(t, "isc f1", enabled(t, "isc-dhcp", FeatureUserClassPool, uc),
		`match if substring(option user-class, 1, 9) = "lab-uc-f1";`,
		`deny members of "f1";`, `allow members of "f1";`, "range 10.200.1.203 10.200.1.210;")
	dn := enabled(t, "dnsmasq", FeatureUserClassPool, uc)
	mustContain(t, "dnsmasq f1", dn,
		"dhcp-userclass=set:f1,lab-uc-f1", "dhcp-range=tag:f1,10.200.1.203,10.200.1.210,12h",
		"dhcp-range=tag:!b5,tag:!f1,10.200.1.100,10.200.1.200,12h")

	f2 := FeatureParams{Seconds: 1800}
	mustContain(t, "kea 108", enabled(t, "kea", FeatureOffer108, f2), `{ "name": "v6-only-preferred", "data": "1800" }`)
	mustContain(t, "isc 108", enabled(t, "isc-dhcp", FeatureOffer108, f2), "option v6-only-preferred 1800;")
	mustContain(t, "dnsmasq 108", enabled(t, "dnsmasq", FeatureOffer108, f2), "dhcp-option=108,00:00:07:08\n")
	if strings.Contains(enabled(t, "dnsmasq", FeatureOffer108, f2), "force") {
		t.Error("offered 108 must not be forced")
	}

	fb := FeatureParams{Seconds: 1800, ClientID: f1ID}
	kc := enabled(t, "kea", FeatureForce108, fb)
	mustContain(t, "kea force", kc, `option[61].hex == 0x006c61622d663262`, `"always-send": true`)
	if strings.Count(kc, "always-send") != 1 || !strings.Contains(kc[strings.Index(kc, `"f2b"`):], `"data": "1800", "always-send"`) {
		t.Error("kea: always-send must sit inside the f2b class only")
	}
	mustContain(t, "isc force", enabled(t, "isc-dhcp", FeatureForce108, fb),
		"match if option dhcp-client-identifier = "+f1ID+";", "encode-int(108, 8)")
	mustContain(t, "dnsmasq force", enabled(t, "dnsmasq", FeatureForce108, fb),
		"dhcp-host=id:"+f1ID+",set:f2b", "dhcp-option-force=tag:f2b,108,00:00:07:08")
	mustContain(t, "dnsmasq rc", enabled(t, "dnsmasq", FeatureRapidCommit4, FeatureParams{}), "\ndhcp-rapid-commit\n")
}

// dnsmasq ShortenLeaseTime still rewrites every range once the user-class scenario added a
// second tag to the main one (the regex took one tag before #20).
func TestDnsmasqShortenCoversTwoTaggedRanges(t *testing.T) {
	cfg := enabled(t, "dnsmasq", FeatureUserClassPool, FeatureParams{Class: "c", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"})
	out := dnsmasqRangeRE.ReplaceAllString(cfg, "${1}120")
	if n := len(regexp.MustCompile(`(?m)^dhcp-range=.*,120$`).FindAllString(out, -1)); n != 3 {
		t.Fatalf("%d of 3 ranges shortened:\n%s", n, out)
	}
}

// A guard that is present but widened ("... or true", "|| ...") scopes
// nothing; every class test must be exactly one equality on the option,
// and the ISC match exactly one comparison (#20).
func TestClassGuardsAreASingleEquality(t *testing.T) {
	kre := regexp.MustCompile(`"name": "(f1|f2b)", "test": "([^"]*)"`)
	uc := FeatureParams{Class: "lab-uc-f1", PoolStart: "10.200.1.203", PoolEnd: "10.200.1.210"}
	fb := FeatureParams{Seconds: 1800, ClientID: f1ID}
	for name, cfg := range map[string]string{
		"f1": enabled(t, "kea", FeatureUserClassPool, uc), "f2b": enabled(t, "kea", FeatureForce108, fb),
	} {
		m := kre.FindStringSubmatch(cfg)
		if m == nil || m[1] != name {
			t.Fatalf("kea %s: class not found", name)
		}
		want := `^option\[(77|61)\]\.hex == 0x[0-9a-f]+$`
		if !regexp.MustCompile(want).MatchString(m[2]) {
			t.Errorf("kea %s test %q is not a single equality", name, m[2])
		}
	}
	isc := regexp.MustCompile(`(?m)^\s*match if ([^;]*);$`)
	for name, cfg := range map[string]string{
		"f1": enabled(t, "isc-dhcp", FeatureUserClassPool, uc), "f2b": enabled(t, "isc-dhcp", FeatureForce108, fb),
	} {
		ms := isc.FindAllStringSubmatch(cfg, -1)
		if len(ms) == 0 {
			t.Fatalf("isc %s: no match line", name)
		}
		for _, m := range ms {
			if strings.Contains(m[1], " or ") || strings.Contains(m[1], " and ") || strings.Contains(m[1], "true") {
				t.Errorf("isc %s match %q is not a single comparison", name, m[1])
			}
		}
	}
}

// The F8-forcerenew snippets per source (defeats 9, 16): 145 and 90 only for the
// client id, 90 = 03 01 00, replay 1, type 1, the nonce; 90 only for a
// message with option 50, so not in a renewal's ACK (RFC 6704 3.1.3).
func TestForceRenewSnippetsAreScopedAndCarryTheNonce(t *testing.T) {
	p := FeatureParams{ClientID: f1ID, Nonce: katNonce}
	const opt90 = "030100" + "0000000000000001" + "01" + "00112233445566778899aabbccddeeff"
	colon90 := hexColon(ForceRenewNonceOption(katNonce))
	if hexPlain(colon90) != opt90 {
		t.Fatalf("option 90 value %s, want %s", hexPlain(colon90), opt90)
	}
	kc := enabled(t, "kea", FeatureForceRenewNonce, p)
	mustContain(t, "kea f8", kc,
		`{ "library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_flex_option.so"`,
		`{ "code": 90, "add": "ifelse(option[61].hex == 0x006c61622d663262 and pkt4.msgtype == 3 and option[50].exists, 0x`+opt90+`, '')" }`,
		`{ "code": 145, "add": "ifelse(option[61].hex == 0x006c61622d663262, 0x01, '')" }`)
	if strings.Count(kc, "libdhcp_lease_cmds.so") != 1 {
		t.Error("kea: the lease_cmds hook must stay exactly once")
	}
	ic := enabled(t, "isc-dhcp", FeatureForceRenewNonce, p)
	mustContain(t, "isc f8", ic,
		"option lab-fr-capable code 145 = unsigned integer 8;", "option lab-fr-auth code 90 = string;",
		"match if option dhcp-client-identifier = "+f1ID+";", "encode-int(145, 8), encode-int(90, 8)",
		"if option dhcp-message-type = 3 and exists dhcp-requested-address {\n    option lab-fr-auth "+colon90+";")
	if strings.Count(ic, "lab-fr-auth") != 2 || strings.Count(ic, "option lab-fr-auth "+colon90) != 1 || strings.Index(ic, "option lab-fr-auth "+colon90) < strings.Index(ic, `class "f8"`) {
		t.Error("isc: option 90 must sit inside the f8 class only")
	}
	dc := enabled(t, "dnsmasq", FeatureForceRenewNonce, p)
	mustContain(t, "dnsmasq f8", dc, "dhcp-host=id:"+f1ID+",set:f8\n",
		"dhcp-match=set:f8sel,option:requested-address\n", "dhcp-option-force=tag:f8,145,01\n", "dhcp-option-force=tag:f8,tag:f8sel,90,"+colon90+"\n")
	if regexp.MustCompile(`(?m)^dhcp-option-force=tag:f8,90,`).MatchString(dc) {
		t.Error("dnsmasq: 90 without the option 50 tag reaches a renewal's ACK")
	}
	if regexp.MustCompile(`(?m)^dhcp-option(-force)?=(145|90),`).MatchString(dc) {
		t.Error("dnsmasq: an untagged 145 or 90 reaches every client")
	}
	for _, m := range regexp.MustCompile(`ifelse\(([^,]*),`).FindAllStringSubmatch(kc, -1) {
		if !regexp.MustCompile(`^option\[61\]\.hex == 0x[0-9a-f]+( and pkt4\.msgtype == 3 and option\[50\]\.exists)?$`).MatchString(m[1]) {
			t.Errorf("kea flex_option guard %q is not the client-id equality", m[1])
		}
	}
}
