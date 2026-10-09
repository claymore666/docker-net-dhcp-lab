package coverage

import "github.com/claymore666/docker-net-dhcp-lab/internal/scenario"

// Entry is one option's recorded coverage: Scenario names the
// scenario.Name that exercises it, or, when nothing does yet, Reason
// says why not. Exactly one of the two is ever set (Check enforces
// this, not this file), so a reader of this file can tell a real gap
// from a documented one at a glance.
type Entry struct {
	Scenario string
	Reason   string
}

// notCoveredOption and notCoveredSetting are the two honest reasons
// every unmapped row below carries: the current scenario set (the only
// one that exists yet) tests plugin lifecycle events -- restart,
// reboot, upgrade, kill, scale -- against whatever driver options and
// plugin settings a cell's lab.yaml happens to be running with; it does
// not yet vary a driver option or a plugin setting to test its own
// documented behaviour. Both strings are reused verbatim so a later
// scenario that starts covering one of these rows changes this file's
// text in one place, not N places (issue #4).
const (
	notCoveredOption  = "not covered yet, planned: no scenario yet sets or varies this driver option"
	notCoveredSetting = "not covered yet, planned: no scenario yet changes this plugin setting"
	notCoveredIPv6    = "not covered yet, planned: today's scenarios are IPv4-only; IPv6 scenarios come later"
)

// Mapping is the lab's one reviewed record of docs/reference.md's
// option tables against what today's scenarios actually exercise
// (issue #4). Seeded honestly from the scenarios that exist today:
// scripts/run-cell.sh's own network bring-up is the only place any
// of these options is set at all (internal/scenario/shape.go's
// NetworkUp, `-o bridge=`/`-o mode=`/`-o parent=`), so mode/bridge/
// parent are the only rows this file credits with a scenario. Every
// other row is a real, current gap, not a placeholder: reviewed and
// updated in the same PR as whatever scenario starts covering it.
var Mapping = map[string]Entry{
	// Driver options (network-level)
	"network:mode":                {Scenario: scenario.NameA1},
	"network:bridge":              {Scenario: scenario.NameA1},
	"network:parent":              {Scenario: scenario.NameA1},
	"network:macvlan_mode":        {Reason: notCoveredOption},
	"network:vlan":                {Reason: notCoveredOption},
	"network:gateway":             {Reason: notCoveredOption},
	"network:ipv6":                {Reason: notCoveredIPv6},
	"network:ipv6_mode":           {Reason: notCoveredIPv6},
	"network:ipv6_main_prefix":    {Reason: notCoveredIPv6},
	"network:ipv6_auto_strict":    {Reason: notCoveredIPv6},
	"network:lease_timeout":       {Scenario: scenario.NameC1},
	"network:conflict_check":      {Reason: notCoveredOption},
	"network:ignore_conflicts":    {Reason: notCoveredOption},
	"network:skip_routes":         {Reason: notCoveredOption},
	"network:propagate_dns":       {Scenario: scenario.NameB6},
	"network:propagate_mtu":       {Reason: notCoveredOption},
	"network:mtu":                 {Reason: notCoveredOption},
	"network:client_id":           {Scenario: scenario.NameB2},
	"network:vendor_class":        {Scenario: scenario.NameB5},
	"network:validate_dhcp":       {Scenario: scenario.NameC11},
	"network:dhcp_servers":        {Reason: notCoveredOption},
	"network:dhcp_deny_servers":   {Reason: notCoveredOption},
	"network:register_dns":        {Scenario: scenario.NameB3},
	"network:audit_log":           {Reason: notCoveredOption},
	"network:release_lease":       {Scenario: scenario.NameB7},
	"network:host_ifname":         {Reason: notCoveredOption},
	"network:force_create":        {Reason: notCoveredOption},
	"network:ipvlan_mode":         {Reason: notCoveredOption},
	"network:require_mac":         {Reason: notCoveredOption},
	"network:link_local_fallback": {Reason: notCoveredOption},

	// Driver options (per-endpoint)
	"endpoint:ip": {Reason: "not covered yet, planned: no scenario yet requests a specific address"},
	"endpoint:com.docker.network.endpoint.ifname": {Reason: "not covered yet, planned: no scenario yet requests a specific interface name"},

	// Plugin settings
	"setting:LOG_LEVEL":     {Reason: notCoveredSetting},
	"setting:AWAIT_TIMEOUT": {Reason: notCoveredSetting},
	"setting:STATE_DIR":     {Reason: notCoveredSetting},
	"setting:METRICS_ADDR":  {Reason: notCoveredSetting},
	"setting:DOCKER_HOST":   {Reason: notCoveredSetting},
}
