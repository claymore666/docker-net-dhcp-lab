package coverage

import (
	"strings"
	"testing"
)

// miniMD is a docs fixture small enough to expand by hand: three
// attachment modes, one option with a family pair partner, a
// restricted-mode option, a boolean, one endpoint row and one setting.
const miniMD = `# Reference

## Driver options (network-level)

| option | modes | default | since | description |
| ------ | ----- | ------- | ----- | ----------- |
| ` + "`mode`" + ` | n/a | ` + "`bridge`" + ` | upstream | Strategy: ` + "`bridge`, `macvlan`, `ipvlan`" + `. |
| ` + "`ipv6_mode`" + ` | all | ` + "`off`" + ` | v2.2.0 | ` + "`off`, `dhcp`, `slaac`" + `. Any other value is refused. Pairs with ` + "`skip_routes`" + `. |
| ` + "`ipv6_pd`" + ` | bridge, macvlan | unset | v2.5.0 | A length, usually ` + "`64`" + `. |
| ` + "`skip_routes`" + ` | all | ` + "`false`" + ` | upstream | A boolean, ` + "`true`" + ` or ` + "`false`" + `. |

## Driver options (per-endpoint)

| option | description |
| ------ | ----------- |
| ` + "`ip`" + ` | An address, as ` + "`docker run --ip`" + `. |

## Plugin settings

| name | default | meaning |
| ---- | ------- | ------- |
| ` + "`LOG_LEVEL`" + ` | ` + "`info`" + ` | ` + "`info` or `debug`" + `. |
`

const miniInventory = `options:
  "network:mode":
    reviewed: "@@network:mode@@"
    no_written_default: true
    mode_path: per-mode
    values:
      - {v: "bridge", class: default, modes: ["bridge"]}
      - {v: "macvlan", class: allowed, modes: ["macvlan"]}
      - {v: "ipvlan", class: allowed, modes: ["ipvlan"]}
  "network:ipv6_mode":
    reviewed: "@@network:ipv6_mode@@"
    families: ["ipv6", "routes"]
    mode_path: per-mode
    values:
      - {v: "off", class: default}
      - {v: "dhcp", class: allowed}
      - {v: "slaac", class: allowed}
      - {v: "bogus", class: refused, no_token: true}
    not_values: ["skip_routes"]
  "network:ipv6_pd":
    reviewed: "@@network:ipv6_pd@@"
    families: ["ipv6", "routes"]
    mode_path: per-mode
    values:
      - {v: "unset", class: default, no_token: true, matches: "unset"}
      - {v: "64", class: allowed}
  "network:skip_routes":
    reviewed: "@@network:skip_routes@@"
    boolean: true
    families: ["routes"]
    mode_path: per-mode
    values:
      - {v: "false", class: default}
      - {v: "true", class: allowed}
  "endpoint:ip":
    reviewed: "@@endpoint:ip@@"
    no_written_default: true
    mode_path: per-mode
    values:
      - {v: "unset", class: default, no_token: true}
      - {v: "192.0.2.50", class: allowed, no_token: true}
    not_values: ["docker run --ip"]
  "setting:LOG_LEVEL":
    reviewed: "@@setting:LOG_LEVEL@@"
    mode_path: n/a
    values:
      - {v: "info", class: default}
      - {v: "debug", class: allowed}
alias_groups: []
env:
  ipv6: ["ipv6_mode=dhcp"]
  routes: ["skip_routes=true"]
`

// miniFixture parses miniMD and fills the row hashes into
// miniInventory, optionally rewriting the inventory text first.
func miniFixture(t *testing.T, edit func(string) string) ([]Row, *Inventory) {
	t.Helper()
	return miniFixtureMD(t, nil, edit)
}

// miniFixtureMD also lets a test rewrite the docs text first.
func miniFixtureMD(t *testing.T, editMD, edit func(string) string) ([]Row, *Inventory) {
	t.Helper()
	md := miniMD
	if editMD != nil {
		md = editMD(md)
	}
	rows, err := ParseRows(md)
	if err != nil {
		t.Fatal(err)
	}
	text := miniInventory
	if edit != nil {
		text = edit(text)
	}
	for _, r := range rows {
		text = strings.ReplaceAll(text, "@@"+r.Key()+"@@", r.Hash)
	}
	inv, err := ParseInventory([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return rows, inv
}

// mustReplace edits fixture text and fails the test when the needle is
// absent, so an edit cannot silently stop applying.
func mustReplace(t *testing.T, s, old, repl string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("fixture has no %q to replace", old)
	}
	return strings.Replace(s, old, repl, 1)
}

func hasProblem(problems []string, parts ...string) bool {
	for _, p := range problems {
		ok := true
		for _, part := range parts {
			ok = ok && strings.Contains(p, part)
		}
		if ok {
			return true
		}
	}
	return false
}
