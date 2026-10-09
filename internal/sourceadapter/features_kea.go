package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
)

var (
	// keaClassesRE and keaMainPoolClassRE anchor the F1 edits on the
	// class list and the main-pool test cloud-init/kea-user-data writes.
	keaClassesRE   = regexp.MustCompile(`("client-classes": \[)`)
	keaNotB5RE     = regexp.MustCompile(`(\{ "name": "not-b5", "test": ")not member\('b5'\)(" \})`)
	keaClassPoolRE = regexp.MustCompile(`(\{ "pool": "[^"]*", "client-class": "b5" \})`)
)

// EnableFeature rewrites the running kea-dhcp4.conf (#20). Kea 2.6.3
// has no DHCPv4 rapid commit (ARM, DHCPv4 page), so FeatureRapidCommit4
// is refused here and the adapter does not declare CapRapidCommit4.
func (a *KeaAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var edits []configEdit
	var already string
	switch f {
	case FeatureUserClassPool:
		already = `"name": "f1"`
		class := fmt.Sprintf(`${1}`+"\n"+`        { "name": "f1", "test": "option[77].hex == 0x%s" },`, hexPlain(v.classHex()))
		edits = []configEdit{
			{keaClassesRE, class, "the client-classes list"},
			{keaNotB5RE, `${1}not member('b5') and not member('f1')${2}`, "the main pool's class test"},
			{keaClassPoolRE, fmt.Sprintf(`${1},`+"\n"+`            { "pool": "%s - %s", "client-class": "f1" }`, v.start, v.end), "the class pool"},
		}
	case FeatureOffer108:
		already = `"v6-only-preferred"`
		edits = []configEdit{{keaRoutersOptionRE, fmt.Sprintf(`${1}, { "name": "v6-only-preferred", "data": "%d" }`, v.seconds), "the subnet option-data"}}
	case FeatureForce108:
		already = `"name": "f2b"`
		class := fmt.Sprintf(`${1}`+"\n"+`        { "name": "f2b", "test": "option[61].hex == 0x%s", "option-data": [ { "name": "v6-only-preferred", "data": "%d", "always-send": true } ] },`, hexPlain(v.clientID), v.seconds)
		edits = []configEdit{{keaClassesRE, class, "the client-classes list"}}
	default:
		return nil, fmt.Errorf("kea: %s is not supported by Kea 2.6.3", f)
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf", already, edits,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}
