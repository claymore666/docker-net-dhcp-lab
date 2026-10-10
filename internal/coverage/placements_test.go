package coverage

import (
	"os"
	"strings"
	"testing"
)

const (
	unitRef = "pkg/plugin/options_test.go:TestOptions"
	intRef  = "test/integration/ipv6_test.go:TestIPv6"
)

func baseInput() Input {
	return Input{
		Variants: []Variant{
			{ID: "ipv6_mode=dhcp@bridge", Kind: KindSingle, Mode: "bridge", Runtime: true},
			{ID: "ipv6_mode=dhcp@macvlan", Kind: KindSingle, Mode: "macvlan", Runtime: true},
			{ID: "ipv6_mode=!bogus", Kind: KindRefused},
		},
		Tests:      map[string]bool{unitRef: true, intRef: true},
		Lab:        []LabScenario{{Name: "plain-lease"}, {Name: "v6-relay", Needs: []string{"v6", "relay"}}},
		Undeclared: map[string]bool{"v6": true, "relay": true, "failover-pair": true},
		ModePath:   map[string]string{"ipv6_mode": "per-mode", "ipv6_pd": "shared"},
		Placements: []Placement{
			{Match: []string{"ipv6_mode=dhcp@bridge", "ipv6_mode=dhcp@macvlan"}, Home: HomeIntegration, Status: StatusCovered,
				Ref: intRef, Assert: "L10", Points: []string{"start", "settled"}},
			{Match: []string{"ipv6_mode=!bogus"}, Home: HomeUnit, Status: StatusCovered, Ref: unitRef, Assert: "L40"},
		},
	}
}

func TestCheckVariants_FixtureIsClean(t *testing.T) {
	res := CheckVariants(baseInput())
	if len(res.Problems) != 0 {
		t.Fatalf("control fixture should be clean: %v", res.Problems)
	}
	if res.Total != 3 || res.Counts["integration/covered"] != 2 || res.Counts["unit/covered"] != 1 {
		t.Errorf("counts = %v total %d", res.Counts, res.Total)
	}
}

func TestCheckVariants_ZeroPlacements(t *testing.T) {
	in := baseInput()
	in.Placements = in.Placements[:1]
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "variant ipv6_mode=!bogus has no placement") {
		t.Fatalf("an unplaced variant must be named: %v", res.Problems)
	}
}

func TestCheckVariants_TwoPlacementsFail(t *testing.T) {
	in := baseInput()
	in.Placements = append(in.Placements, Placement{Match: []string{"ipv6_mode=dhcp@*"}, Home: HomeUnit, Status: StatusNA, Reason: "x"})
	in.ModePath["ipv6_mode"] = "shared"
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "ipv6_mode=dhcp@bridge has 2 placements") {
		t.Fatalf("two matching placements must fail: %v", res.Problems)
	}
}

func TestCheckVariants_PlacementMatchingNothingFails(t *testing.T) {
	in := baseInput()
	in.Placements = append(in.Placements, Placement{Match: []string{"ipv6_mode=slaac@bridge"}, Home: HomeUnit, Status: StatusNA, Reason: "x"})
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "placement #3", "matches no variant") {
		t.Fatalf("a placement matching no variant must fail (a stale ID after a rename): %v", res.Problems)
	}
}

func TestCheckVariants_GlobOnAnOptionNameFails(t *testing.T) {
	in := baseInput()
	in.Placements = append(in.Placements, Placement{Match: []string{"ipv6_*=dhcp@bridge"}, Home: HomeUnit, Status: StatusNA, Reason: "x"})
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "wildcards an option name") {
		t.Fatalf("an option-name glob must fail: %v", res.Problems)
	}
}

func TestCheckVariants_ANewOptionIsNotSwallowedByAnOptionGlob(t *testing.T) {
	// Every placement names its options, so an option added to the docs
	// after the placements were written has no placement.
	in := baseInput()
	in.Variants = append(in.Variants, Variant{ID: "brand_new=on@bridge", Kind: KindSingle, Mode: "bridge", Runtime: true})
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "variant brand_new=on@bridge has no placement") {
		t.Fatalf("a new option must surface as unplaced: %v", res.Problems)
	}
}

func TestCheckVariants_ModeGlobNeedsASharedModePath(t *testing.T) {
	in := baseInput()
	in.Placements[0].Match = []string{"ipv6_mode=dhcp@*"}
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "mode glob", "ipv6_mode", "per-mode") {
		t.Fatalf("a mode glob on a per-mode option must fail: %v", res.Problems)
	}
	// Control: the same glob is legal where the option is shared.
	in.ModePath["ipv6_mode"] = "shared"
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Fatalf("a mode glob on a shared option should pass: %v", res.Problems)
	}
}

func TestCheckVariants_RuntimeAliasOnAUnitRefOnlyFails(t *testing.T) {
	alias := Variant{ID: "alias:ipv6=true~ipv6=1@bridge", Kind: KindAlias, Mode: "bridge", Runtime: true}
	mk := func(p Placement) Input {
		in := baseInput()
		in.Variants = []Variant{alias}
		in.Placements = []Placement{p}
		return in
	}
	unit := Placement{Match: []string{alias.ID}, Home: HomeUnit, Status: StatusCovered, Ref: unitRef, Assert: "L1", Points: []string{"start", "settled"}}
	if res := CheckVariants(mk(unit)); !hasProblem(res.Problems, "runtime alias", "unit ref only", "#1125") {
		t.Fatalf("a runtime alias on a unit ref only must fail: %v", res.Problems)
	}
	// Controls: an integration ref, a unit ref with an integration also.
	integ := Placement{Match: []string{alias.ID}, Home: HomeIntegration, Status: StatusCovered, Ref: intRef, Assert: "L1", Points: []string{"start", "settled"}}
	if res := CheckVariants(mk(integ)); len(res.Problems) != 0 {
		t.Errorf("an integration ref should pass: %v", res.Problems)
	}
	unit.Also = []string{intRef}
	if res := CheckVariants(mk(unit)); len(res.Problems) != 0 {
		t.Errorf("a unit ref with an integration also should pass: %v", res.Problems)
	}
	// A create-time alias may sit on a unit ref.
	alias2 := Variant{ID: "alias:mode=empty~mode=unset", Kind: KindAlias}
	in := baseInput()
	in.Variants = []Variant{alias2}
	in.Placements = []Placement{{Match: []string{alias2.ID}, Home: HomeUnit, Status: StatusCovered, Ref: unitRef, Assert: "L1"}}
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Errorf("a decode-time alias on a unit ref should pass: %v", res.Problems)
	}
}

func TestCheckVariants_CoveredLabRefNeedingAnUndeclaredCapabilityIsAGap(t *testing.T) {
	in := baseInput()
	in.Placements[0] = Placement{Match: []string{"ipv6_mode=dhcp@bridge", "ipv6_mode=dhcp@macvlan"}, Home: HomeLab, Status: StatusCovered,
		Ref: "v6-relay", Assert: "L1", Points: []string{"start", "settled"}}
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "v6-relay", "needs capability", "a gap, not coverage") {
		t.Fatalf("a lab ref nobody can run must not count as coverage: %v", res.Problems)
	}
	if res.Counts["lab/covered"] != 0 || res.Counts["lab/gap"] != 2 {
		t.Errorf("counts must report it as a gap: %v", res.Counts)
	}
	// Control: a scenario needing nothing undeclared is plain coverage.
	in.Placements[0].Ref = "plain-lease"
	if res := CheckVariants(in); len(res.Problems) != 0 || res.Counts["lab/covered"] != 2 {
		t.Errorf("a runnable lab ref should pass: %v %v", res.Problems, res.Counts)
	}
}

func TestCheckVariants_GapNeedsARealIssueRef(t *testing.T) {
	for _, issue := range []string{"#TBD", "#12", "", "claymore666/docker-net-dhcp", "claymore666/docker-net-dhcp#", "TBD"} {
		in := baseInput()
		in.Placements[1] = Placement{Match: []string{"ipv6_mode=!bogus"}, Home: HomeUnit, Status: StatusGap, Issue: issue}
		if res := CheckVariants(in); !hasProblem(res.Problems, "gap needs an issue of the form owner/repo#N") {
			t.Errorf("issue %q should be refused: %v", issue, res.Problems)
		}
	}
	in := baseInput()
	in.Placements[1] = Placement{Match: []string{"ipv6_mode=!bogus"}, Home: HomeUnit, Status: StatusGap, Issue: "claymore666/docker-net-dhcp-lab#48"}
	res := CheckVariants(in)
	if len(res.Problems) != 0 || res.Counts["unit/gap"] != 1 {
		t.Errorf("a real issue ref should pass: %v %v", res.Problems, res.Counts)
	}
}

func TestCheckVariants_NAWithoutAReasonFails(t *testing.T) {
	for _, reason := range []string{"", "   "} {
		in := baseInput()
		in.Placements[1] = Placement{Match: []string{"ipv6_mode=!bogus"}, Home: HomeUnit, Status: StatusNA, Reason: reason}
		if res := CheckVariants(in); !hasProblem(res.Problems, "na needs a reason") {
			t.Errorf("reason %q should be refused: %v", reason, res.Problems)
		}
	}
	in := baseInput()
	in.Placements[1] = Placement{Match: []string{"ipv6_mode=!bogus"}, Home: HomeUnit, Status: StatusNA, Reason: "refused in a path the docs state only"}
	if res := CheckVariants(in); len(res.Problems) != 0 || res.Counts["unit/na"] != 1 {
		t.Errorf("an N/A with a reason should pass: %v %v", res.Problems, res.Counts)
	}
}

func TestCheckVariants_RuntimeNeedsStartOrStartNA(t *testing.T) {
	in := baseInput()
	in.Placements[0].Points = []string{"settled"}
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "ipv6_mode=dhcp@bridge needs a start point or a start_na reason") {
		t.Fatalf("a runtime variant read only once settled must fail: %v", res.Problems)
	}
	// Controls: start in points, or a start_na reason.
	in.Placements[0].Points = []string{"start", "settled"}
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Errorf("start in points should pass: %v", res.Problems)
	}
	in.Placements[0].Points = []string{"settled"}
	in.Placements[0].StartNA = "the option is only read once the lease settles"
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Errorf("a start_na reason should pass: %v", res.Problems)
	}
	// A create-time variant needs neither.
	in = baseInput()
	in.Placements[1].Points = nil
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Errorf("a create-time variant needs no points: %v", res.Problems)
	}
}

func TestCheckVariants_RefMissingFromTestsTxt(t *testing.T) {
	in := baseInput()
	in.Tests = map[string]bool{intRef: true}
	res := CheckVariants(in)
	if !hasProblem(res.Problems, unitRef, "not in tests.txt") {
		t.Fatalf("a renamed or deleted plugin test must surface: %v", res.Problems)
	}
	in = baseInput()
	in.Placements[1].Also = []string{"pkg/plugin/gone_test.go:TestGone"}
	if res := CheckVariants(in); !hasProblem(res.Problems, "also", "gone_test.go", "not in tests.txt") {
		t.Errorf("an also ref is checked the same way: %v", res.Problems)
	}
}

func TestCheckVariants_RefMissingFromTheCatalog(t *testing.T) {
	in := baseInput()
	in.Placements[0].Home = HomeLab
	in.Placements[0].Ref = "no-such-scenario"
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "no-such-scenario", "neither a lab scenario of the catalog nor a plugin test path") {
		t.Fatalf("an unknown lab ref must fail: %v", res.Problems)
	}
}

func TestCheckVariants_RefKindMustMatchHome(t *testing.T) {
	refs := map[string]string{HomeUnit: unitRef, HomeIntegration: intRef, HomeLab: "plain-lease"}
	for refKind, ref := range refs {
		for home := range refs {
			in := baseInput()
			in.Placements[1] = Placement{Match: []string{"ipv6_mode=!bogus"}, Home: home, Status: StatusCovered, Ref: ref, Assert: "L40"}
			res := CheckVariants(in)
			mismatch := hasProblem(res.Problems, "is a "+refKind+" ref but the placement's home is "+home)
			if refKind == home && len(res.Problems) != 0 {
				t.Errorf("a %s ref under home %s should pass: %v", refKind, home, res.Problems)
			}
			if refKind != home && !mismatch {
				t.Errorf("a %s ref under home %s must fail on the kind: %v", refKind, home, res.Problems)
			}
		}
	}
}

func TestCheckVariants_RuntimeAliasAlsoRefMustReallyRun(t *testing.T) {
	alias := Variant{ID: "alias:ipv6=true~ipv6=1@bridge", Kind: KindAlias, Mode: "bridge", Runtime: true}
	mk := func(also ...string) Input {
		in := baseInput()
		in.Variants = []Variant{alias}
		in.Placements = []Placement{{Match: []string{alias.ID}, Home: HomeUnit, Status: StatusCovered, Ref: unitRef, Assert: "L1",
			Points: []string{"start", "settled"}, Also: also}}
		return in
	}
	// A lab scenario that needs a capability no adapter declares runs
	// nowhere, so it does not stand for the Join side of the alias.
	if res := CheckVariants(mk("v6-relay")); !hasProblem(res.Problems, "runtime alias", "unit ref only") {
		t.Errorf("a gated lab also must not satisfy the runtime-alias rule: %v", res.Problems)
	}
	// An integration also that is not in tests.txt is no test either.
	in := mk(intRef)
	in.Tests = map[string]bool{unitRef: true}
	if res := CheckVariants(in); !hasProblem(res.Problems, "runtime alias", "unit ref only") {
		t.Errorf("an integration also missing from tests.txt must not satisfy it: %v", res.Problems)
	}
	// Controls: a runnable lab also, and a real integration also.
	for _, ok := range []string{"plain-lease", intRef} {
		if res := CheckVariants(mk(ok)); len(res.Problems) != 0 {
			t.Errorf("also %s should satisfy the rule: %v", ok, res.Problems)
		}
	}
}

func TestCheckVariants_PointsAreStartOrSettled(t *testing.T) {
	in := baseInput()
	in.Placements[0].Points = []string{"start", "settled", "bogus"}
	if res := CheckVariants(in); !hasProblem(res.Problems, `point "bogus" is not start or settled`) {
		t.Fatalf("an unknown point must fail: %v", res.Problems)
	}
	in = baseInput()
	in.Placements[0].Points = []string{"start"}
	if res := CheckVariants(in); !hasProblem(res.Problems, "needs a settled point") {
		t.Fatalf("a runtime placement that never reads the settled state must fail: %v", res.Problems)
	}
	// A create-time variant reads neither.
	in = baseInput()
	in.Placements[1].Points = nil
	if res := CheckVariants(in); len(res.Problems) != 0 {
		t.Errorf("a create-time variant needs no points: %v", res.Problems)
	}
}

func TestCheckVariants_CoveredNeedsRefAndAssert(t *testing.T) {
	in := baseInput()
	in.Placements[1].Ref = ""
	if res := CheckVariants(in); !hasProblem(res.Problems, "covered without a ref") {
		t.Errorf("no ref: %v", res.Problems)
	}
	in = baseInput()
	in.Placements[1].Assert = ""
	if res := CheckVariants(in); !hasProblem(res.Problems, "covered without an assert line") {
		t.Errorf("no assert: %v", res.Problems)
	}
}

func TestCheckVariants_UnknownHomeAndStatus(t *testing.T) {
	in := baseInput()
	in.Placements[1].Home = "elsewhere"
	in.Placements[1].Status = "maybe"
	res := CheckVariants(in)
	if !hasProblem(res.Problems, `home "elsewhere"`) || !hasProblem(res.Problems, `status "maybe"`) {
		t.Fatalf("unknown home and status must fail: %v", res.Problems)
	}
}

func TestCheckVariants_EmptyMatchAndBadPattern(t *testing.T) {
	in := baseInput()
	in.Placements = append(in.Placements, Placement{Home: HomeUnit, Status: StatusNA, Reason: "x"},
		Placement{Match: []string{"nonsense"}, Home: HomeUnit, Status: StatusNA, Reason: "x"})
	res := CheckVariants(in)
	if !hasProblem(res.Problems, "has no match patterns") || !hasProblem(res.Problems, `"nonsense"`, "not opt=value") {
		t.Fatalf("empty and malformed matches must fail: %v", res.Problems)
	}
}

func TestCheckVariants_ProblemsAreSorted(t *testing.T) {
	in := baseInput()
	in.Placements = nil
	res := CheckVariants(in)
	for i := 1; i < len(res.Problems); i++ {
		if res.Problems[i-1] > res.Problems[i] {
			t.Fatalf("problems not sorted: %v", res.Problems)
		}
	}
	if len(res.Problems) != 3 {
		t.Errorf("want one problem per unplaced variant, got %v", res.Problems)
	}
}

func TestCheckVariants_PatternValueGlobNeverStandsForARefusedValue(t *testing.T) {
	in := baseInput()
	in.Placements[0].Match = []string{"ipv6_mode=*@bridge", "ipv6_mode=*@macvlan"}
	in.Placements[1].Match = []string{"ipv6_mode=!*"}
	res := CheckVariants(in)
	if len(res.Problems) != 0 {
		t.Fatalf("value globs should place their own kind: %v", res.Problems)
	}
	// A plain * must not swallow the refused variant.
	in.Placements[1].Match = []string{"ipv6_mode=*@bridge"}
	res = CheckVariants(in)
	if !hasProblem(res.Problems, "variant ipv6_mode=!bogus has no placement") {
		t.Errorf("ipv6_mode=* must not match a refused value: %v", res.Problems)
	}
}

func TestParsePlacements_UnknownFieldIsAnError(t *testing.T) {
	if _, err := ParsePlacements([]byte("placements:\n  - match: [\"a=b@bridge\"]\n    hom: unit\n")); err == nil {
		t.Fatal("a misspelt placement field must be an error")
	}
	if _, err := ParsePlacements([]byte("placment: []\n")); err == nil {
		t.Fatal("a misspelt top-level field must be an error")
	}
	ps, err := ParsePlacements([]byte("placements:\n  - match: [\"a=b@bridge\"]\n    home: unit\n    status: na\n    reason: r\n"))
	if err != nil || len(ps) != 1 || ps[0].Home != HomeUnit {
		t.Fatalf("control parse failed: %v %v", ps, err)
	}
}

func TestShippedPlacementsFileIsEmptyInPR1(t *testing.T) {
	data, err := os.ReadFile("data/placements.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := ParsePlacements(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 {
		t.Fatalf("PR 1 ships no placements; got %d", len(ps))
	}
	if !strings.Contains(string(data), "placements") {
		t.Error("the file must still declare the key")
	}
}

func TestCheckVariants_TwoPatternsOfOnePlacementCountOnce(t *testing.T) {
	// A placement is the unit: two of its patterns matching one variant
	// is one placement, not two.
	in := baseInput()
	in.Placements[0].Match = []string{"ipv6_mode=dhcp@bridge", "ipv6_mode=*@bridge", "ipv6_mode=dhcp@macvlan"}
	res := CheckVariants(in)
	if len(res.Problems) != 0 {
		t.Fatalf("overlapping patterns of one placement must count once: %v", res.Problems)
	}
	if res.Counts["integration/covered"] != 2 {
		t.Errorf("counts = %v", res.Counts)
	}
}

func TestCheckVariants_GapAndNANeedNoStartPoint(t *testing.T) {
	// Only a covered placement reads the variant; a gap or an N/A on a
	// runtime variant has nothing to read at start.
	in := baseInput()
	in.Placements[0] = Placement{Match: []string{"ipv6_mode=dhcp@bridge"}, Home: HomeIntegration, Status: StatusGap, Issue: "claymore666/docker-net-dhcp-lab#48"}
	in.Placements = append(in.Placements, Placement{Match: []string{"ipv6_mode=dhcp@macvlan"}, Home: HomeUnit, Status: StatusNA, Reason: "not reachable in macvlan"})
	res := CheckVariants(in)
	if len(res.Problems) != 0 {
		t.Fatalf("a gap or N/A on a runtime variant needs no points: %v", res.Problems)
	}
	if res.Counts["integration/gap"] != 1 || res.Counts["unit/na"] != 1 {
		t.Errorf("counts = %v", res.Counts)
	}
}
