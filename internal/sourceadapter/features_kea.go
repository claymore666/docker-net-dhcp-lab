package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
)

var (
	// keaClassesRE and keaMainPoolClassRE anchor the user-class edits on the
	// class list and the main-pool test cloud-init/kea-user-data writes.
	keaClassesRE   = regexp.MustCompile(`("client-classes": \[)`)
	keaNotB5RE     = regexp.MustCompile(`(\{ "name": "not-b5", "test": ")not member\('b5'\)(" \})`)
	keaClassPoolRE = regexp.MustCompile(`(\{ "pool": "[^"]*", "client-class": "b5" \})`)
	// keaLeaseCmdsHookRE anchors the flex_option hook on the lease_cmds
	// line and reuses its directory, which is per architecture.
	keaLeaseCmdsHookRE = regexp.MustCompile(`(\{ "library": "([^"]*/)libdhcp_lease_cmds\.so" \})`)
	// keaRapidCommit6RE anchors on the subnet6 flag kea-dhcp6.conf
	// carries off at baseline (cloud-init/kea-user-data).
	keaRapidCommit6RE = regexp.MustCompile(`"rapid-commit": false`)
	// keaPool6RE anchors on the one-line subnet6 pools list; the v4 pools
	// span lines, so only the v6 one matches (cloud-init/kea-user-data).
	keaPool6RE = regexp.MustCompile(`("pools": \[ \{ "pool": "[0-9a-f:]+ - [0-9a-f:]+" \} \])`)
)

// EnableFeature rewrites the running kea-dhcp4.conf (#20). Kea 2.6.3
// has no DHCPv4 rapid commit (ARM, DHCPv4 page), so FeatureRapidCommit4
// is refused here and the adapter does not declare CapRapidCommit4.
// FeatureRapidCommit6 edits kea-dhcp6.conf instead. Kea 2.6.3 grants
// no IA_TA whatever the config (MEASURED 2026-10-09,
// #23), so FeatureTemporary6 is refused and CapTemporary6 not declared.
func (a *KeaAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	switch f {
	case FeatureRapidCommit6:
		edits := []configEdit{{keaRapidCommit6RE, `"rapid-commit": true`, "the subnet6 rapid-commit flag"}}
		return enableFeatureViaSubstitution(ctx, a.Runner, keaDHCP6Conf, `"rapid-commit": true`, edits, a.restart6, "kea")
	case FeaturePD:
		// Kea ARM "Subnet and Prefix Delegation Pools": /64 per client (#23).
		pd := fmt.Sprintf(`${1}, "pd-pools": [ { "prefix": "%s", "prefix-len": %d, "delegated-len": 64 } ]`, v.pdPool.Addr(), v.pdPool.Bits())
		edits := []configEdit{{keaPool6RE, pd, "the subnet6 pools list"}}
		return enableFeatureViaSubstitution(ctx, a.Runner, keaDHCP6Conf, `"pd-pools"`, edits, a.restart6, "kea")
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
	case FeatureForceRenewNonce:
		// Kea refuses an option-def for 90; flex_option adds it, and its
		// expression sees the query: a REQUEST with option 50 selects the
		// first ACK, not the renewal's (RFC 6704 3.1.3, RFC 2131 table 5;
		// MEASURED 2.6.3, lab #21).
		already = "libdhcp_flex_option"
		id := hexPlain(v.clientID)
		hook := fmt.Sprintf(`${1},`+"\n"+`        { "library": "${2}libdhcp_flex_option.so", "parameters": { "options": [ { "code": 90, "add": "ifelse(option[61].hex == 0x%s and pkt4.msgtype == 3 and option[50].exists, 0x%s, '')" }, { "code": 145, "add": "ifelse(option[61].hex == 0x%s, 0x01, '')" } ] } }`, id, hexPlain(v.auth90Hex()), id)
		edits = []configEdit{{keaLeaseCmdsHookRE, hook, "the lease_cmds hook line"}}
	default:
		return nil, fmt.Errorf("kea: %s is not supported by Kea 2.6.3", f)
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, "/etc/kea/kea-dhcp4.conf", already, edits,
		func(ctx context.Context) error { return a.Restart(ctx) }, "kea")
}
