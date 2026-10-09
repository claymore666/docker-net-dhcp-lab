package coverage

import (
	"os"
	"strings"
	"testing"
)

func miniVariants(t *testing.T) []Variant {
	t.Helper()
	rows, inv := miniFixture(t, nil)
	vs, err := Generate(rows, inv)
	if err != nil {
		t.Fatal(err)
	}
	return vs
}

// TestGenerate_Golden pins the fixture's expansion. The count was worked
// out by hand: singles 30 (LOG_LEVEL 2, ip 2x3, ipv6_mode 3x3, ipv6_pd
// 2x2, mode 3, skip_routes 2x3), refused 1, outofmode 1 (ipv6_pd in
// ipvlan), aliases 8, pairs 12 (ipv6_mode x ipv6_pd 2x1x2 modes, plus
// skip_routes against each of them), env 18 (ipv6 4 profiles x 3 modes,
// routes 2 profiles x 3 modes).
func TestGenerate_Golden(t *testing.T) {
	vs := miniVariants(t)
	got := FormatMatrix(vs)
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile("testdata/mini-matrix.tsv", []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/mini-matrix.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("matrix differs from testdata/mini-matrix.tsv; run with UPDATE_GOLDEN=1 only if the hand count still holds\n%s", got)
	}
	wantCounts := map[string]int{"single": 30, "refused": 1, "outofmode": 1, "alias": 8, "pair": 12, "env": 18}
	counts := Counts(vs)
	for k, n := range wantCounts {
		if counts[k] != n {
			t.Errorf("kind %s: got %d, hand count %d", k, counts[k], n)
		}
	}
	if len(vs) != 70 {
		t.Errorf("total %d, hand count 70", len(vs))
	}
}

func TestGenerate_EnvProfilesAreExactlyTheTable(t *testing.T) {
	vs := miniVariants(t)
	have := map[string]map[string]bool{}
	for _, v := range vs {
		if v.Kind != KindEnv {
			continue
		}
		id, err := ParseID(v.ID)
		if err != nil {
			t.Fatal(err)
		}
		key := id.A[0].String() + "@" + id.Mode
		if have[key] == nil {
			have[key] = map[string]bool{}
		}
		have[key][id.Profile] = true
	}
	for _, m := range AllModes {
		ipv6 := have["ipv6_mode=dhcp@"+m]
		for _, p := range []string{"E1", "E2", "E3", "E4"} {
			if !ipv6[p] {
				t.Errorf("ipv6 family lacks %s in %s", p, m)
			}
		}
		routes := have["skip_routes=true@"+m]
		if len(routes) != 2 || !routes["E1"] || !routes["E3"] {
			t.Errorf("routes family must take H only (E1, E3) in %s, got %v", m, routes)
		}
	}
	// The table itself: a covering array over H, P and D, where every
	// pair of axes shows all four combinations.
	if len(Profiles) != 4 {
		t.Fatalf("want 4 profiles, have %d", len(Profiles))
	}
	want := []struct {
		name     string
		host     string
		prefixes int
		offered  bool
	}{
		{"E1", "kernel", 1, true}, {"E2", "kernel", 2, false},
		{"E3", "network manager", 1, false}, {"E4", "network manager", 2, true},
	}
	for i, w := range want {
		p := Profiles[i]
		if p.Name != w.name || p.Host != w.host || p.Prefixes != w.prefixes || p.Offered != w.offered {
			t.Errorf("profile %d = %+v, want %+v", i, p, w)
		}
	}
	pairs := map[string]bool{}
	for _, p := range Profiles {
		pairs["HP"+p.Host+string(rune('0'+p.Prefixes))] = true
		pairs["HD"+p.Host+boolStr(p.Offered)] = true
		pairs["PD"+string(rune('0'+p.Prefixes))+boolStr(p.Offered)] = true
	}
	if len(pairs) != 12 {
		t.Errorf("profiles do not cover every pair of axes: %d of 12 combinations", len(pairs))
	}
}

func boolStr(b bool) string {
	if b {
		return "T"
	}
	return "F"
}

func TestGenerate_RefusesAnInventoryThatDoesNotMatchTheDocs(t *testing.T) {
	rows, inv := miniFixture(t, nil)
	delete(inv.Options, "network:ipv6_pd")
	if _, err := Generate(rows, inv); err == nil || !strings.Contains(err.Error(), "network:ipv6_pd") {
		t.Fatalf("Generate must refuse an invalid inventory, got %v", err)
	}
}

func TestGenerate_PairWithADefaultSideIsNoRow(t *testing.T) {
	for _, v := range miniVariants(t) {
		if v.Kind != KindPair {
			continue
		}
		for _, bad := range []string{"ipv6_mode=off", "ipv6_pd=unset", "skip_routes=false"} {
			if strings.Contains(v.ID, bad) {
				t.Errorf("%s pairs a default value (%s); a default side is not an interaction", v.ID, bad)
			}
		}
	}
}

func TestGenerate_PointsPerKind(t *testing.T) {
	for _, v := range miniVariants(t) {
		want := "start,settled"
		switch v.Kind {
		case KindRefused, KindOutOfMode, KindAlias:
			want = "create"
		}
		if v.Points() != want {
			t.Errorf("%s: points %q, want %q", v.ID, v.Points(), want)
		}
	}
}

func TestGenerate_OutOfModeOnlyForRestrictedRows(t *testing.T) {
	var got []string
	for _, v := range miniVariants(t) {
		if v.Kind == KindOutOfMode {
			got = append(got, v.ID)
		}
	}
	if len(got) != 1 || got[0] != "ipv6_pd@!ipvlan" {
		t.Errorf("out-of-mode variants = %v, want only ipv6_pd@!ipvlan", got)
	}
	for _, v := range miniVariants(t) {
		if strings.HasPrefix(v.ID, "ipv6_pd=") && strings.HasSuffix(v.ID, "@ipvlan") {
			t.Errorf("%s: a restricted option has no value variant in a mode it does not support", v.ID)
		}
	}
}

func TestGenerate_AliasesAreThoseTheInventoryAndTheRulesImply(t *testing.T) {
	var got []string
	for _, v := range miniVariants(t) {
		if v.Kind == KindAlias {
			got = append(got, v.ID)
		}
	}
	for _, want := range []string{
		"alias:skip_routes=1~skip_routes=true",
		"alias:skip_routes=0~skip_routes=false",
		"alias:ipv6_mode=off~ipv6_mode=unset",
		"alias:mode=empty~mode=unset",
	} {
		if !containsStr(got, want) {
			t.Errorf("missing alias %s", want)
		}
	}
	// A written default is no alias for an option that has none, and an
	// endpoint option with no_written_default has no empty spelling rule
	// beyond the generic one.
	for _, no := range []string{"alias:mode=bridge~mode=unset", "alias:ip=192.0.2.50~ip=unset"} {
		if containsStr(got, no) {
			t.Errorf("unexpected alias %s", no)
		}
	}
}

func TestGenerate_IsDeterministic(t *testing.T) {
	a := FormatMatrix(miniVariants(t))
	b := FormatMatrix(miniVariants(t))
	if a != b {
		t.Fatal("two runs gave different matrices")
	}
}

func TestGenerate_EveryIDParsesAndRoundTrips(t *testing.T) {
	for _, v := range miniVariants(t) {
		id, err := ParseID(v.ID)
		if err != nil {
			t.Errorf("%s: %v", v.ID, err)
			continue
		}
		if id.String() != v.ID {
			t.Errorf("%s round-trips to %s", v.ID, id.String())
		}
		if id.Kind != v.Kind {
			t.Errorf("%s: kind %s, ID says %s", v.ID, v.Kind, id.Kind)
		}
	}
}

func variantIDs(vs []Variant) map[string]Variant {
	m := map[string]Variant{}
	for _, v := range vs {
		m[v.ID] = v
	}
	return m
}

func TestGenerate_RefusedPairIsDecidedAtCreateNotAtStart(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		s = mustReplace(t, s, `{v: "64", class: allowed}`, `{v: "64", class: allowed, refuses_with: ["skip_routes=true"]}`)
		// A pair no family or docs row generates: only the declaration does.
		return mustReplace(t, s, `{v: "slaac", class: allowed}`, `{v: "slaac", class: allowed, refuses_with: ["ip=192.0.2.50"]}`)
	})
	vs, err := Generate(rows, inv)
	if err != nil {
		t.Fatal(err)
	}
	by := variantIDs(vs)
	for _, id := range []string{"pair:ipv6_pd=64+skip_routes=true@bridge", "pair:ipv6_pd=64+skip_routes=true@macvlan", "pair:ip=192.0.2.50+ipv6_mode=slaac@bridge"} {
		v, ok := by[id]
		if !ok {
			t.Fatalf("%s is missing", id)
		}
		if v.Runtime || v.Points() != "create" || v.Kind != KindPair {
			t.Errorf("%s: a refused pair is decided at create (runtime %v, points %s)", id, v.Runtime, v.Points())
		}
	}
	// Controls: the sibling pair the docs do not refuse stays a runtime read,
	// and ipvlan carries no ipv6_pd pair at all.
	if v := by["pair:ipv6_mode=dhcp+ipv6_pd=64@bridge"]; !v.Runtime {
		t.Errorf("an unrefused pair must stay a runtime variant: %+v", v)
	}
	if _, ok := by["pair:ipv6_pd=64+skip_routes=true@ipvlan"]; ok {
		t.Error("a pair is generated only in the modes both options allow")
	}
}

func TestGenerate_RefusesWithMustNameARealNonRefusedValue(t *testing.T) {
	for _, target := range []string{"nosuchopt=1", "skip_routes=maybe", "ipv6_mode=bogus", "skip_routes"} {
		rows, inv := miniFixture(t, func(s string) string {
			return mustReplace(t, s, `{v: "64", class: allowed}`, `{v: "64", class: allowed, refuses_with: ["`+target+`"]}`)
		})
		if _, err := Generate(rows, inv); err == nil || !strings.Contains(err.Error(), "refuses_with") {
			t.Errorf("refuses_with %q must fail the generator, got %v", target, err)
		}
	}
}

func TestGenerate_AliasSpelledPairIsNotASecondRow(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, "alias_groups: []", `alias_groups:
  - name: "dhcp-and-skip"
    modes: ["bridge", "macvlan", "ipvlan"]
    runtime: true
    members: ["ipv6_mode=dhcp", "ipv6_mode=dhcp+skip_routes=true"]`)
	})
	vs, err := Generate(rows, inv)
	if err != nil {
		t.Fatal(err)
	}
	by := variantIDs(vs)
	if _, ok := by["alias:ipv6_mode=dhcp~ipv6_mode=dhcp+skip_routes=true@bridge"]; !ok {
		t.Error("the alias row must stay")
	}
	if _, ok := by["pair:ipv6_mode=dhcp+skip_routes=true@bridge"]; ok {
		t.Error("the alias spelling's configuration is counted twice: alias and pair")
	}
	// Control: the same options with another value are a real pair.
	if _, ok := by["pair:ipv6_mode=slaac+skip_routes=true@bridge"]; !ok {
		t.Error("an unrelated pair of the same options must stay")
	}
}

func TestGenerate_NamedPairUsesThePartnerValue(t *testing.T) {
	// ipv6_mode names skip_routes, and nothing else pairs them: leave
	// the shared family out so only the docs-named pair can produce it.
	edit := func(partner string) func(string) string {
		return func(s string) string {
			s = mustReplace(t, s, `families: ["ipv6", "routes"]
    mode_path: per-mode
    values:
      - {v: "off", class: default}`, `families: ["ipv6"]
    mode_path: per-mode
    values:
      - {v: "off", class: default}`)
			s = mustReplace(t, s, `families: ["routes"]`, `families: []`)
			return mustReplace(t, s, `{v: "slaac", class: allowed}`, `{v: "slaac", class: allowed`+partner+`}`)
		}
	}
	for _, c := range []struct{ partner, want, notWant string }{
		{"", "pair:ipv6_mode=dhcp+skip_routes=true@bridge", "pair:ipv6_mode=slaac+skip_routes=true@bridge"},
		{", partner: true", "pair:ipv6_mode=slaac+skip_routes=true@bridge", "pair:ipv6_mode=dhcp+skip_routes=true@bridge"},
	} {
		rows, inv := miniFixture(t, edit(c.partner))
		vs, err := Generate(rows, inv)
		if err != nil {
			t.Fatal(err)
		}
		by := variantIDs(vs)
		if _, ok := by[c.want]; !ok {
			t.Errorf("partner %q: %s is missing", c.partner, c.want)
		}
		if _, ok := by[c.notWant]; ok {
			t.Errorf("partner %q: %s must not be generated", c.partner, c.notWant)
		}
	}
}

func TestGenerate_TokenKindRefusedValueNeedsNoLiteral(t *testing.T) {
	addExample := func(md string) string {
		return mustReplace(t, md, "A boolean, ", "A boolean (a prefix such as `192.0.2.7/24` is refused), ")
	}
	line := `      - {v: "true", class: allowed}
`
	good := func(s string) string {
		return mustReplace(t, s, `  "network:skip_routes":
    reviewed: "@@network:skip_routes@@"
    boolean: true
    families: ["routes"]
    mode_path: per-mode
    values:
      - {v: "false", class: default}
`+line, `  "network:skip_routes":
    reviewed: "@@network:skip_routes@@"
    boolean: true
    families: ["routes"]
    mode_path: per-mode
    values:
      - {v: "false", class: default}
`+line+`      - {v: "192.0.2.7/24", class: refused, no_token: true, token_kind: ipv4-prefix-length}
`)
	}
	rows, inv := miniFixtureMD(t, addExample, func(s string) string {
		// The new token is also in not_values unless a value claims it.
		return good(s)
	})
	if p := inv.Validate(rows); len(p) != 0 {
		t.Fatalf("a token_kind value should account for the example token: %v", p)
	}
	vs, err := Generate(rows, inv)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := variantIDs(vs)["skip_routes=!192.0.2.7/24"]; !ok || v.Kind != KindRefused || v.Points() != "create" {
		t.Errorf("the refused example must be a create-time refusal: %+v %v", v, ok)
	}
	// Controls: the same docs without the kind leave the token unclassed.
	rows, inv = miniFixtureMD(t, addExample, nil)
	if p := inv.Validate(rows); !hasProblem(p, "192.0.2.7/24", "neither as a value nor in not_values") {
		t.Errorf("an unclassed example token must fail: %v", p)
	}
}

// A pair the docs refuse is decided at create whichever generator added
// it first; the builder must not depend on the order of the passes.
func TestBuilder_RefusedPairIsCreateTimeWhicheverPassAddedItFirst(t *testing.T) {
	id := ID{Kind: KindPair, A: []Term{{"a", "1"}}, B: []Term{{"b", "2"}}, Mode: "bridge"}
	for _, order := range []string{"runtime-then-refused", "refused-then-runtime", "marked-then-runtime-only"} {
		b := &builder{byID: map[string]*Variant{}, refused: map[string]bool{}, spelled: map[string]bool{}}
		switch order {
		case "runtime-then-refused":
			b.add(id, true, "ipv6")
			b.refused[id.String()] = true
			b.add(id, false, "refused")
		case "refused-then-runtime":
			b.refused[id.String()] = true
			b.add(id, false, "refused")
			b.add(id, true, "routes")
		default:
			b.refused[id.String()] = true
			b.add(id, true, "routes")
		}
		if v := b.byID[id.String()]; v == nil || v.Runtime {
			t.Errorf("%s: a refused pair must stay create-time: %+v", order, v)
		}
	}
}

// A variant naming a value the docs refuse in its mode is decided at
// create whichever pass added it first (#35).
func TestBuilder_ValueRefusedInAModeIsCreateTimeWhicheverPassAddedItFirst(t *testing.T) {
	id := ID{Kind: KindSingle, A: []Term{{"a", "1"}}, Mode: "ipvlan"}
	for _, order := range []string{"runtime-then-marked", "marked-then-runtime"} {
		b := &builder{byID: map[string]*Variant{}, refused: map[string]bool{}, spelled: map[string]bool{}, modeRefused: map[string]bool{}}
		if order == "runtime-then-marked" {
			b.add(id, true, "")
			b.modeRefused["a=1@ipvlan"] = true
			b.add(id, true, "")
		} else {
			b.modeRefused["a=1@ipvlan"] = true
			b.add(id, true, "")
			b.add(id, true, "env")
		}
		if v := b.byID[id.String()]; v == nil || v.Runtime {
			t.Errorf("%s: refused in ipvlan, must stay create-time: %+v", order, v)
		}
	}
	other := ID{Kind: KindSingle, A: []Term{{"a", "1"}}, Mode: "bridge"}
	b := &builder{byID: map[string]*Variant{}, refused: map[string]bool{}, spelled: map[string]bool{}, modeRefused: map[string]bool{"a=1@ipvlan": true}}
	b.add(other, true, "")
	if v := b.byID[other.String()]; v == nil || !v.Runtime {
		t.Errorf("a refusal in ipvlan must not reach bridge: %+v", v)
	}
}

// TestGenerate_ValueRefusedInOneModeIsDecidedAtCreateInThatModeOnly: the
// docs refuse ipv6_mode=slaac in ipvlan (#35, reference.md ipv6_mode), so
// the single, the env rows and every pair naming it there are create-time
// rows, and the same value in the other modes stays a runtime read.
func TestGenerate_ValueRefusedInOneModeIsDecidedAtCreateInThatModeOnly(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		s = mustReplace(t, s, `ipv6: ["ipv6_mode=dhcp"]`, `ipv6: ["ipv6_mode=dhcp", "ipv6_mode=slaac"]`)
		return mustReplace(t, s, `{v: "slaac", class: allowed}`, `{v: "slaac", class: allowed, refused_modes: ["ipvlan"]}`)
	})
	vs, err := Generate(rows, inv)
	if err != nil {
		t.Fatal(err)
	}
	by := variantIDs(vs)
	create := []string{"ipv6_mode=slaac@ipvlan", "env:ipv6_mode=slaac@ipvlan#E1", "env:ipv6_mode=slaac@ipvlan#E4", "pair:ipv6_mode=slaac+skip_routes=true@ipvlan"}
	run := []string{"ipv6_mode=slaac@bridge", "ipv6_mode=slaac@macvlan", "env:ipv6_mode=slaac@bridge#E1", "env:ipv6_mode=slaac@macvlan#E3", "pair:ipv6_mode=slaac+skip_routes=true@bridge",
		"ipv6_mode=dhcp@ipvlan", "env:ipv6_mode=dhcp@ipvlan#E1", "pair:ipv6_mode=dhcp+skip_routes=true@ipvlan"}
	for _, id := range create {
		v, ok := by[id]
		if !ok {
			t.Errorf("%s is missing", id)
		} else if v.Runtime || v.Points() != "create" {
			t.Errorf("%s: refused in ipvlan, so decided at create (runtime %v)", id, v.Runtime)
		}
	}
	for _, id := range run {
		v, ok := by[id]
		if !ok {
			t.Errorf("%s is missing", id)
		} else if !v.Runtime || v.Points() != "start,settled" {
			t.Errorf("%s: accepted there, so a runtime read (runtime %v)", id, v.Runtime)
		}
	}
}
