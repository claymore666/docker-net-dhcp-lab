package scenario

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// allNeeds is the union of what the catalog needs: a source that declares
// all of it, so Applicable never answers before the shape does.
func allNeeds() []sourceadapter.Capability {
	seen := map[sourceadapter.Capability]bool{}
	var caps []sourceadapter.Capability
	for _, s := range Catalog {
		for _, n := range s.Needs {
			if !seen[n] {
				seen[n] = true
				caps = append(caps, n)
			}
		}
	}
	return caps
}

// readyHost answers the plugin probes like fakeRunOneHostRunner and says yes
// to every host-bridge check, so RunOne reaches the scenario body.
type readyHost struct{ plugin *fakeRunOneHostRunner }

func (h readyHost) Run(ctx context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, "PluginReference") || strings.Contains(cmd, "pgrep") {
		return h.plugin.Run(ctx, cmd)
	}
	return "", nil
}

func staticEnv(t *testing.T, shape Shape, src sourceadapter.Adapter) Env {
	t.Helper()
	return Env{
		Host: readyHost{&fakeRunOneHostRunner{installed: true, pgrepOK: true}}, Source: src, Cell: "kea", Shape: shape,
		GitSHA: "abc1234", HostInfo: HostInfo{Distro: "debian", Kernel: "6.1.0", DockerVersion: "27.0"}, EvidenceDir: t.TempDir(),
	}
}

func ipamShapes() []Shape { return []Shape{ShapeBridgeIPAM, ShapeMacvlanIPAM} }

// Drift: what the scenario bodies answer on an ipam shape with nothing to
// run against, set against the table, in both directions. A scenario that
// reaches the host or the source panics on the nil and is not static.
func TestStaticNATableMatchesTheScenarios(t *testing.T) {
	for _, shape := range ipamShapes() {
		observed := map[string]string{}
		for _, s := range Catalog {
			func() {
				defer func() { _ = recover() }()
				e := Env{Cell: "kea", Shape: shape, GitSHA: "abc1234"}
				v := s.Run(context.Background(), e)
				if v.Result != NA {
					return
				}
				for _, network := range []string{optionNetworkWhat, c9NetworkWhat} {
					if want, _ := ipamNA(s.Name, e, network); want.Reason == v.Reason {
						observed[s.Name] = network
					}
				}
			}()
		}
		var missing, extra []string
		for name, network := range observed {
			if ipamStaticNA[name] != network {
				missing = append(missing, name)
			}
		}
		for name := range ipamStaticNA {
			if _, ok := observed[name]; !ok {
				extra = append(extra, name)
			}
		}
		sort.Strings(missing)
		sort.Strings(extra)
		if len(missing) > 0 || len(extra) > 0 {
			t.Errorf("%s: scenarios answering the ipam N/A first but absent or wrong in ipamStaticNA: %v; table rows no scenario answers: %v", shape, missing, extra)
		}
		if len(observed) == 0 {
			t.Fatalf("%s: no scenario answered the ipam N/A; the drift check sees nothing", shape)
		}
	}
}

func TestStaticNATableNamesOnlyCatalogScenarios(t *testing.T) {
	for name := range ipamStaticNA {
		scenarioNamed(t, name)
	}
}

// On a shape without the ipam refusal no scenario is static, whatever the
// table says.
func TestStaticNAEmptyOnNonIPAMShapes(t *testing.T) {
	src := &fakeAdapter{caps: allNeeds()}
	for _, shape := range Shapes {
		if shape == ShapeBridgeIPAM || shape == ShapeMacvlanIPAM {
			continue
		}
		for _, s := range Catalog {
			_, shapeRow := shapeStaticNA[s.Name]
			if v, ok := StaticNA(s, staticEnv(t, shape, src)); ok && !(shapeRow && shape == ShapeIpvlan) {
				t.Errorf("%s on %s answered statically: %s", s.Name, shape, v.Reason)
			}
		}
	}
}

// Drift for the non-ipam shape rows, both directions: what the bodies
// answer on ipvlan with nothing to run against, set against shapeStaticNA.
func TestShapeStaticNATableMatchesTheScenarios(t *testing.T) {
	observed := map[string]bool{}
	for _, s := range Catalog {
		func() {
			defer func() { _ = recover() }()
			e := Env{Cell: "kea", Shape: ShapeIpvlan, GitSHA: "abc1234"}
			v := s.Run(context.Background(), e)
			if f, ok := shapeStaticNA[s.Name]; ok {
				if want, _ := f(e); v.Result == NA && want.Reason == v.Reason {
					observed[s.Name] = true
				}
			}
		}()
	}
	for name := range shapeStaticNA {
		if !observed[name] {
			t.Errorf("shapeStaticNA row %s: the scenario body does not answer it first on ipvlan", name)
		}
	}
	if len(observed) == 0 {
		t.Fatal("no scenario answered the ipvlan N/A; the drift check sees nothing")
	}
}

// A shape row answers only on its own shape, and writes the wrapper's bytes.
func TestStaticNAAnswersC6OnIpvlanOnlyAndMatchesTheWrapper(t *testing.T) {
	src := &fakeAdapter{caps: allNeeds()}
	c6 := scenarioNamed(t, NameC6)
	for _, shape := range Shapes {
		_, ok := StaticNA(c6, staticEnv(t, shape, src))
		if want := shape == ShapeIpvlan || shape == ShapeBridgeIPAM || shape == ShapeMacvlanIPAM; ok != want {
			t.Errorf("C6 on %s: static %v, want %v", shape, ok, want)
		}
	}
	e := staticEnv(t, ShapeIpvlan, src)
	got, _ := StaticNA(c6, e)
	want := RunOne(context.Background(), c6, e)
	if want.Result != NA || want.Reason != got.Reason {
		t.Fatalf("wrapper %s %q, static %q", want.Result, want.Reason, got.Reason)
	}
	a, b := t.TempDir(), t.TempDir()
	if err := Write(a, got); err != nil {
		t.Fatal(err)
	}
	if err := Write(b, want); err != nil {
		t.Fatal(err)
	}
	if x, y := verdictBytes(t, a), verdictBytes(t, b); x != y {
		t.Errorf("bytes differ\nstatic:\n%s\nwrapper:\n%s", x, y)
	}
}

// The skipped verdict is the one the wrapper writes: same file bytes but
// the timestamp, which is the moment each was made.
func TestStaticNAVerdictBytesEqualTheWrapperVerdict(t *testing.T) {
	src := &fakeAdapter{caps: allNeeds()}
	n := 0
	for _, shape := range ipamShapes() {
		for _, s := range Catalog {
			if _, ok := ipamStaticNA[s.Name]; !ok {
				continue
			}
			e := staticEnv(t, shape, src)
			got, ok := StaticNA(s, e)
			if !ok {
				t.Errorf("%s on %s: not answered statically", s.Name, shape)
				continue
			}
			want := RunOne(context.Background(), s, e)
			if want.Result != NA {
				t.Errorf("%s on %s: the wrapper answered %s (%s), not N/A", s.Name, shape, want.Result, want.Reason)
				continue
			}
			a, b := t.TempDir(), t.TempDir()
			if err := Write(a, got); err != nil {
				t.Fatal(err)
			}
			if err := Write(b, want); err != nil {
				t.Fatal(err)
			}
			if x, y := verdictBytes(t, a), verdictBytes(t, b); x != y {
				t.Errorf("%s on %s: bytes differ\nstatic:\n%s\nwrapper:\n%s", s.Name, shape, x, y)
			}
			if !strings.Contains(verdictBytes(t, a), "host.kernel: 6.1.0") {
				t.Errorf("%s on %s: the static verdict lost the host fields", s.Name, shape)
			}
			n++
		}
	}
	if n != 2*len(ipamStaticNA) {
		t.Fatalf("compared %d verdicts, want %d", n, 2*len(ipamStaticNA))
	}
}

func verdictBytes(t *testing.T, dir string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "*.verdict"))
	if len(files) != 1 {
		t.Fatalf("%s: %d verdict files, want 1", dir, len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, l := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(l, "timestamp:") {
			keep = append(keep, l)
		}
	}
	return filepath.Base(files[0]) + "\n" + strings.Join(keep, "\n")
}

// What RunOne checks before the scenario body keeps its own answer: a
// source that lacks the capability gets the capability reason, and a
// source type with a shape reason gets that reason.
type shapeReasonSource struct {
	*fakeAdapter
	why string
}

func (s shapeReasonSource) NAShapeReason(string, string) string { return s.why }

func TestStaticNAKeepsTheCapabilityAndShapeReasons(t *testing.T) {
	b2 := scenarioNamed(t, NameB2)

	var without []sourceadapter.Capability
	for _, c := range allNeeds() {
		if c != sourceadapter.CapReserveClientID {
			without = append(without, c)
		}
	}
	e := staticEnv(t, ShapeBridgeIPAM, &fakeAdapter{caps: without})
	if _, ok := StaticNA(b2, e); ok {
		t.Error("B2 answered statically for a source without reserve-client-id")
	}
	v := RunOne(context.Background(), b2, e)
	if v.Result != NA || !strings.Contains(v.Reason, "does not declare capability") {
		t.Errorf("RunOne kept neither the N/A nor the capability reason: %s %q", v.Result, v.Reason)
	}

	e = staticEnv(t, ShapeBridgeIPAM, shapeReasonSource{&fakeAdapter{caps: allNeeds()}, "this server cannot do it"})
	if _, ok := StaticNA(b2, e); ok {
		t.Error("B2 answered statically although the source type has a shape reason")
	}
	v = RunOne(context.Background(), b2, e)
	if v.Result != NA || v.Reason != "this server cannot do it" {
		t.Errorf("RunOne lost the source type's reason: %s %q", v.Result, v.Reason)
	}

	// a scenario outside the table is never answered here
	if _, ok := StaticNA(scenarioNamed(t, NameA1), staticEnv(t, ShapeBridgeIPAM, &fakeAdapter{caps: allNeeds()})); ok {
		t.Error("A1 answered statically")
	}
}
