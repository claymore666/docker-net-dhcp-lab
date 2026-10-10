package coverage

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
)

// TestPinnedMatrixIsCurrent regenerates the matrix from the newest
// pinned reference.md and the inventory, and requires it to equal the
// checked-in matrix.tsv. It needs no network, so verify.sh's go test
// runs it: a hand edit of the inventory or the generator that moves the
// matrix fails here until matrix.tsv is regenerated and reviewed.
func TestPinnedMatrixIsCurrent(t *testing.T) {
	fsys := Data()
	tag, err := LatestPinned(fsys)
	if err != nil {
		t.Fatal(err)
	}
	l, err := LoadPinnedMatrix(fsys, tag)
	if err != nil {
		t.Fatal(err)
	}
	if d := MatrixDiff(fsys, l.Variants); d != "" {
		t.Fatalf("%s: %s", tag, d)
	}
	if p := l.Inventory.Validate(l.Rows); len(p) != 0 {
		t.Fatalf("the inventory does not account for the pinned docs: %v", p)
	}
}

// TestPinnedMatrixCountsAreStated keeps the numbers the PR quotes
// tied to the data, so a quiet change shows in review.
func TestPinnedMatrixCountsAreStated(t *testing.T) {
	l, err := LoadPinnedMatrix(Data(), "v2.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Rows) != 43 {
		t.Errorf("v2.5.0 has %d rows, want 43 (35 network, 2 endpoint, 6 settings)", len(l.Rows))
	}
	if got := len(l.Variants); got != 827 {
		t.Errorf("v2.5.0 matrix has %d variants, the PR description says 827", got)
	}
	want := map[string]int{KindSingle: 244, KindRefused: 33, KindOutOfMode: 17, KindAlias: 103, KindPair: 370, KindEnv: 60}
	for kind, n := range Counts(l.Variants) {
		if want[kind] != n {
			t.Errorf("v2.5.0 matrix has %d %s variants, the PR description says %d", n, kind, want[kind])
		}
	}
}

// TestMappingScenariosExistInCatalog stops a credit from naming a
// scenario that was renamed or never registered.
func TestMappingScenariosExistInCatalog(t *testing.T) {
	have := map[string]bool{}
	for _, s := range scenario.Catalog {
		have[s.Name] = true
	}
	for key, e := range Mapping {
		if e.Scenario != "" && !have[e.Scenario] {
			t.Errorf("Mapping[%q] credits scenario %q, which is not in scenario.Catalog", key, e.Scenario)
		}
	}
}

// TestPinnedMappingKeysAreRealRows keeps the old mapping and the new
// inventory describing the same set of docs rows.
func TestPinnedMappingKeysAreRealRows(t *testing.T) {
	l, err := LoadPinnedMatrix(Data(), "v2.5.0")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, r := range l.Rows {
		rows[r.Key()] = true
	}
	for key := range Mapping {
		if !rows[key] {
			t.Errorf("Mapping has %q, which is not a row of the pinned v2.5.0 reference", key)
		}
	}
	for key := range rows {
		if _, ok := Mapping[key]; !ok {
			t.Errorf("pinned v2.5.0 row %q is not in Mapping", key)
		}
	}
}

func realVariants(t *testing.T) map[string]Variant {
	t.Helper()
	l, err := LoadPinnedMatrix(Data(), "v2.5.0")
	if err != nil {
		t.Fatal(err)
	}
	return variantIDs(l.Variants)
}

// TestPinnedMatrixKnowsTheGatewayRefusals: the gateway refuses a prefix
// length, IPv6, unspecified, loopback, multicast and broadcast; each is
// a create-time refusal row, and the prefix length is a real row, not a
// token parked in not_values (reference.md, gateway).
func TestPinnedMatrixKnowsTheGatewayRefusals(t *testing.T) {
	by := realVariants(t)
	for _, v := range []string{"192.0.2.1/24", "2001:db8::1", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"} {
		id := "gateway=!" + v
		got, ok := by[id]
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		if got.Runtime || got.Points() != "create" || got.Kind != KindRefused {
			t.Errorf("%s must be a create-time refusal: %+v", id, got)
		}
	}
	if _, ok := by["require_mac=!maybe"]; !ok {
		t.Error("require_mac refuses a non-boolean value; the row is missing")
	}
}

// TestPinnedMatrixNamedPairsUseTheDocsNamedValue: the docs name
// macvlan_mode=passthru as the one require_mac refuses, so the pair
// is built with it and not with the row's first non-default value.
func TestPinnedMatrixNamedPairsUseTheDocsNamedValue(t *testing.T) {
	by := realVariants(t)
	if v, ok := by["pair:macvlan_mode=passthru+require_mac=true@macvlan"]; !ok || v.Runtime {
		t.Errorf("the passthru+require_mac pair must exist as a create-time refusal: %+v %v", v, ok)
	}
	if _, ok := by["pair:macvlan_mode=vepa+require_mac=true@macvlan"]; ok {
		t.Error("vepa+require_mac is not the pair the docs name")
	}
}

// TestPinnedMatrixRefusedCombinationsAreNotRuntimePairs: combinations
// the docs refuse at create are decided at create, never (start,
// settled) reads of a network that cannot exist.
func TestPinnedMatrixRefusedCombinationsAreNotRuntimePairs(t *testing.T) {
	by := realVariants(t)
	for _, id := range []string{
		"pair:mtu=68+propagate_mtu=true@bridge",
		"pair:ipv6_mode=dhcp+mtu=68@bridge",
		"pair:ipv6=true+mtu=68@bridge",
		"pair:ipv6_mode=dhcp+link_local_fallback=true@bridge",
		"pair:ipv6_mode=slaac+link_local_fallback=true@bridge",
		"pair:lease_timeout=60s+link_local_fallback=true@bridge",
		"pair:ipv6_mode=slaac+ipv6_pd=64@bridge",
		"pair:ipv6_mode=off+ipv6_pd=64@macvlan",
		"pair:ipv6_mode=slaac+ipv6_temporary=true@macvlan",
		"pair:ipv6_iid=stable-privacy+ipv6_mode=dhcp@bridge",
		"pair:ipv6_iid=stable-privacy+ipv6_mode=off@macvlan",
		"pair:ipv6_main_prefix=2001:db8:1::/64+ipv6_mode=dhcp@bridge",
	} {
		v, ok := by[id]
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		if v.Runtime || v.Points() != "create" {
			t.Errorf("%s is refused by the docs and must be a create-time row: %+v", id, v)
		}
	}
	// Control: the docs say rapid_commit under slaac changes nothing; it
	// is not refused, so it stays a runtime pair.
	if v, ok := by["pair:ipv6_mode=slaac+rapid_commit=true@bridge"]; ok && !v.Runtime {
		t.Errorf("slaac+rapid_commit is not a documented refusal: %+v", v)
	}
	if _, ok := by["pair:ipv6=true+ipv6_mode=dhcp@bridge"]; ok {
		t.Error("ipv6=true+ipv6_mode=dhcp is the alias spelling; it must not also be a pair")
	}
}

// TestInventoryHasNoEscapedAddressSpelling: a hygiene scan is not
// passed by spelling an address with escapes; the data files hold the
// documentation address as plain text or not at all.
func TestInventoryHasNoEscapedAddressSpelling(t *testing.T) {
	b, err := fs.ReadFile(Data(), "inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `\x`) || strings.Contains(string(b), `\u00`) {
		t.Error("inventory.yaml spells something with an escape; write it plainly")
	}
}

// TestPinnedMatrixRefusesSlaacAndAutoInIpvlan: the docs refuse
// ipv6_mode=slaac and auto in mode=ipvlan at network creation
// (reference.md, ipv6_mode), so no variant naming either there is a
// (start, settled) read; the same values in bridge and macvlan are.
func TestPinnedMatrixRefusesSlaacAndAutoInIpvlan(t *testing.T) {
	l, err := LoadPinnedMatrix(Data(), "v2.5.0")
	if err != nil {
		t.Fatal(err)
	}
	refusedIn := map[string]int{}
	for _, v := range l.Variants {
		id, err := ParseID(v.ID)
		if err != nil {
			t.Fatal(err)
		}
		named := false
		for _, term := range id.A {
			named = named || term.Opt == "ipv6_mode" && (term.Val == "slaac" || term.Val == "auto")
		}
		if !named || id.Kind == KindAlias {
			continue
		}
		switch id.Mode {
		case "ipvlan":
			refusedIn[id.Kind]++
			if v.Runtime || v.Points() != "create" {
				t.Errorf("%s: refused in ipvlan by the docs, so decided at create: %+v", v.ID, v)
			}
		default:
			if id.Mode != "" && !v.Runtime && id.Kind != KindPair {
				t.Errorf("%s: accepted in %s, so a runtime read: %+v", v.ID, id.Mode, v)
			}
		}
	}
	// The two singles and the env rows (two values, four profiles) must exist.
	if refusedIn[KindSingle] != 2 || refusedIn[KindEnv] != 8 || refusedIn[KindPair] == 0 {
		t.Errorf("ipvlan rows naming slaac or auto: %v, want 2 singles, 8 env and some pairs", refusedIn)
	}
}

// TestPinnedMatrixRefusesIpv6MainPrefixBesideOff: the docs accept
// ipv6_main_prefix only with ipv6_mode=slaac and auto (reference.md,
// ipv6_main_prefix), so beside off it is refused at network creation in
// every mode (#35); beside slaac and auto the pair stays a runtime read.
func TestPinnedMatrixRefusesIpv6MainPrefixBesideOff(t *testing.T) {
	by := realVariants(t)
	for _, prefix := range []string{"2001:db8:1::/64", "2001:db8:ffff::/64"} {
		for _, mode := range []string{"bridge", "macvlan", "ipvlan"} {
			id := "pair:ipv6_main_prefix=" + prefix + "+ipv6_mode=off@" + mode
			v, ok := by[id]
			if !ok {
				t.Errorf("%s is missing", id)
				continue
			}
			if v.Runtime || v.Points() != "create" {
				t.Errorf("%s is refused by the docs and must be a create-time row: %+v", id, v)
			}
		}
		id := "pair:ipv6_main_prefix=" + prefix + "+ipv6_mode=slaac@bridge"
		if v, ok := by[id]; !ok || !v.Runtime {
			t.Errorf("%s is accepted by the docs and must stay a runtime pair: %+v %v", id, v, ok)
		}
	}
}
