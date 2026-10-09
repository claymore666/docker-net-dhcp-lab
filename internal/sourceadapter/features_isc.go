package sourceadapter

import (
	"context"
	"fmt"
	"regexp"
)

var (
	// iscSubnetRE, iscMainPoolDenyRE and iscRoutersRE anchor on the
	// lines cloud-init/isc-dhcp-user-data writes.
	iscSubnetRE       = regexp.MustCompile(`(?m)^([ \t]*)(subnet )`)
	iscMainPoolDenyRE = regexp.MustCompile(`(?m)^([ \t]*)(deny members of "b5";)`)
	iscRoutersLineRE  = regexp.MustCompile(`(?m)^([ \t]*)(option routers [^;]*;)`)
)

// EnableFeature rewrites the running dhcpd.conf (#20). ISC dhcpd 4.4.3
// has no DHCPv4 rapid commit (dhcp-options(5) lists only dhcp6.rapid-commit),
// so FeatureRapidCommit4 is refused and CapRapidCommit4 is not declared.
func (a *ISCDHCPAdapter) EnableFeature(ctx context.Context, f Feature, p FeatureParams) (func(context.Context) error, error) {
	v, err := validateFeature(f, p)
	if err != nil {
		return nil, err
	}
	var edits []configEdit
	var already string
	switch f {
	case FeatureUserClassPool:
		already = `class "f1"`
		class := fmt.Sprintf("${1}class \"f1\" {\n${1}  match if substring(option user-class, 1, %d) = \"%s\";\n${1}}\n${1}${2}", len(v.class), v.class)
		pool := fmt.Sprintf("${1}pool {\n${1}  allow members of \"f1\";\n${1}  range %s %s;\n${1}}\n${1}${2}", v.start, v.end)
		edits = []configEdit{
			{iscSubnetRE, class, "the subnet block"},
			{iscMainPoolDenyRE, "${1}${2}\n${1}deny members of \"f1\";", "the main pool's deny line"},
			{iscRoutersLineRE, pool, "the routers option"},
		}
	case FeatureOffer108:
		already = "option v6-only-preferred"
		edits = []configEdit{{iscRoutersLineRE, fmt.Sprintf("${1}${2}\n${1}option v6-only-preferred %d;", v.seconds), "the routers option"}}
	case FeatureForce108:
		already = `class "f2b"`
		class := fmt.Sprintf("${1}class \"f2b\" {\n${1}  match if option dhcp-client-identifier = %s;\n${1}  option v6-only-preferred %d;\n${1}  option dhcp-parameter-request-list = concat(option dhcp-parameter-request-list, encode-int(108, 8));\n${1}}\n${1}${2}", v.clientID, v.seconds)
		edits = []configEdit{{iscSubnetRE, class, "the subnet block"}}
	case FeatureForceRenewNonce:
		// 90 only for a REQUEST with option 50: the first ACK, not the
		// OFFER or a renewal's ACK (RFC 6704 3.1.3, RFC 2131 table 5;
		// MEASURED 4.4.3-P1, lab #21).
		already = `class "f8"`
		class := fmt.Sprintf("${1}option lab-fr-capable code 145 = unsigned integer 8;\n${1}option lab-fr-auth code 90 = string;\n${1}class \"f8\" {\n${1}  match if option dhcp-client-identifier = %s;\n${1}  option lab-fr-capable 1;\n${1}  option dhcp-parameter-request-list = concat(option dhcp-parameter-request-list, encode-int(145, 8), encode-int(90, 8));\n${1}  if option dhcp-message-type = 3 and exists dhcp-requested-address {\n${1}    option lab-fr-auth %s;\n${1}  }\n${1}}\n${1}${2}", v.clientID, v.auth90Hex())
		edits = []configEdit{{iscSubnetRE, class, "the subnet block"}}
	default:
		return nil, fmt.Errorf("isc-dhcp: %s is not supported by ISC dhcpd 4.4.3", f)
	}
	return enableFeatureViaSubstitution(ctx, a.Runner, "/etc/dhcp/dhcpd.conf", already, edits,
		func(ctx context.Context) error { return a.Restart(ctx) }, "isc-dhcp")
}
