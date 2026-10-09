package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
)

var (
	// dnsmasqMainRangeRE and dnsmasqClassRangeRE anchor on the two
	// ranges cloud-init/dnsmasq-user-data writes.
	dnsmasqMainRangeRE  = regexp.MustCompile(`(?m)^(dhcp-range=tag:!b5,)`)
	dnsmasqClassRangeRE = regexp.MustCompile(`(?m)^(dhcp-range=tag:b5,[^\n]*)$`)
)

// EnableFeature rewrites the running /etc/dnsmasq.conf (#20). Option 108
// goes in as hex bytes: dnsmasq reads a bare number for an option it has
// no type for as one or two bytes, not the four RFC 8925 wants.
func (a *DnsmasqAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var edits []configEdit
	var already string
	switch f {
	case FeatureUserClassPool:
		already = "dhcp-userclass=set:f1,"
		repl := fmt.Sprintf("${1}\ndhcp-userclass=set:f1,%s\ndhcp-range=tag:f1,%s,%s,12h", v.class, v.start, v.end)
		edits = []configEdit{
			{dnsmasqMainRangeRE, "${1}tag:!f1,", "the main range"},
			{dnsmasqClassRangeRE, repl, "the class range"},
		}
	case FeatureOffer108:
		already = "dhcp-option=108,"
		edits = []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-option=108,%s", v.hex108()), "the router option"}}
	case FeatureForce108:
		already = "set:f2b"
		edits = []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-host=id:%s,set:f2b\ndhcp-option-force=tag:f2b,108,%s", v.clientID, v.hex108()), "the router option"}}
	case FeatureForceRenewNonce:
		// dnsmasq has no per-message-type option, so 90 rides in the
		// OFFER too (MEASURED 2.91, lab #21); the client reads it only
		// from the ACK.
		already = "set:f8"
		edits = []configEdit{{dnsmasqRouterOptionRE, fmt.Sprintf("${1}\ndhcp-host=id:%s,set:f8\ndhcp-option-force=tag:f8,145,01\ndhcp-option-force=tag:f8,90,%s", v.clientID, v.auth90Hex()), "the router option"}}
	case FeatureRapidCommit4:
		already = "dhcp-rapid-commit"
		edits = []configEdit{{dnsmasqRouterOptionRE, "${1}\ndhcp-rapid-commit", "the router option"}}
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, "/etc/dnsmasq.conf", already, edits,
		func(ctx context.Context) error { return a.Restart(ctx) }, "dnsmasq")
}
