package coverage

import (
	"strings"
	"testing"
)

func TestInventory_FixtureIsAccountedFor(t *testing.T) {
	rows, inv := miniFixture(t, nil)
	if p := inv.Validate(rows); len(p) != 0 {
		t.Fatalf("the fixture inventory should account for every row: %v", p)
	}
}

func TestInventory_RowNotInInventory(t *testing.T) {
	rows, inv := miniFixture(t, nil)
	delete(inv.Options, "network:ipv6_pd")
	if p := inv.Validate(rows); !hasProblem(p, "network:ipv6_pd", "not in inventory.yaml") {
		t.Fatalf("a docs row with no entry must fail: %v", p)
	}
}

func TestInventory_InventoryRowNotInDocs(t *testing.T) {
	rows, inv := miniFixture(t, nil)
	inv.Options["network:renamed_option"] = inv.Options["network:ipv6_pd"]
	if p := inv.Validate(rows); !hasProblem(p, "network:renamed_option", "not a row of the docs") {
		t.Fatalf("an entry with no docs row must fail: %v", p)
	}
}

func TestInventory_UnclassifiedTokenFails(t *testing.T) {
	// A value added to the docs in backticks is a token nobody classed.
	md := strings.Replace(miniMD, "`off`, `dhcp`, `slaac`", "`off`, `dhcp`, `slaac`, `auto`", 1)
	rows, err := ParseRows(md)
	if err != nil {
		t.Fatal(err)
	}
	_, inv := miniFixture(t, nil)
	p := inv.Validate(rows)
	if !hasProblem(p, "token `auto`", "classed neither as a value nor in not_values") {
		t.Fatalf("a new backticked value must fail as unclassified: %v", p)
	}
}

func TestInventory_ValueTokenNotInRowFails(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `- {v: "dhcp", class: allowed}`, `- {v: "dhcp", class: allowed}
      - {v: "auto", class: allowed}`)
	})
	if p := inv.Validate(rows); !hasProblem(p, "auto", "the docs row does not carry") {
		t.Fatalf("a value spelled as a token the row lacks must fail unless no_token: %v", p)
	}
}

func TestInventory_TokenClassedTwiceFails(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `not_values: ["skip_routes"]`, `not_values: ["skip_routes", "dhcp"]`)
	})
	if p := inv.Validate(rows); !hasProblem(p, "`dhcp` is classed twice") {
		t.Fatalf("a token that is a value and a not-value must fail: %v", p)
	}
}

func TestInventory_DefaultNotInValuesFails(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `- {v: "off", class: default}`, `- {v: "off", class: allowed}
      - {v: "zero", class: default, no_token: true}`)
	})
	if p := inv.Validate(rows); !hasProblem(p, "ipv6_mode", "docs default \"off\" is not among the values") {
		t.Fatalf("a parsed default that no default-class value stands for must fail: %v", p)
	}
}

func TestInventory_NeedsExactlyOneDefault(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `- {v: "slaac", class: allowed}`, `- {v: "slaac", class: default}`)
	})
	if p := inv.Validate(rows); !hasProblem(p, "ipv6_mode", "exactly one default-class value, has 2") {
		t.Fatalf("two defaults must fail: %v", p)
	}
}

func TestInventory_NotValuesMayNotHoldTheDefaultOrAValueToken(t *testing.T) {
	// The rubber stamp: parking the parsed default, or the option's own
	// opt=value token, in not_values would let it pass unclassed.
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `not_values: ["skip_routes"]`, `not_values: ["skip_routes", "ipv6_mode=dhcp"]`)
	})
	rows[1].Tokens = append(rows[1].Tokens, "ipv6_mode=dhcp")
	if p := inv.Validate(rows); !hasProblem(p, "not_values holds `ipv6_mode=dhcp`", "value spelling") {
		t.Fatalf("an own opt=value token in not_values must fail: %v", p)
	}
	rows2, inv2 := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `- {v: "off", class: default}`, `- {v: "zero", class: default, no_token: true, matches: "off"}`)
	})
	inv2.Options["network:ipv6_mode"].NotValues = append(inv2.Options["network:ipv6_mode"].NotValues, "off")
	if p := inv2.Validate(rows2); !hasProblem(p, "not_values holds the parsed default") {
		t.Fatalf("the parsed default in not_values must fail: %v", p)
	}
}

func TestInventory_ValueSpellingsMayNotCollideWithTheIDGrammar(t *testing.T) {
	for _, bad := range []string{"a@b", "a+b", "a~b", "a#b", "a=b", "!a", "*", "a b", ""} {
		rows, inv := miniFixture(t, nil)
		inv.Options["network:ipv6_pd"].Values = append(inv.Options["network:ipv6_pd"].Values,
			ValueSpec{V: bad, Class: ClassAllowed, NoToken: true})
		if p := inv.Validate(rows); !hasProblem(p, "cannot sit inside a variant ID") {
			t.Errorf("value %q should fail: %v", bad, p)
		}
	}
}

func TestInventory_ChangedRowHashFailsUntilReviewed(t *testing.T) {
	// Measured on v2.4.0 to v2.5.0: 13 new values arrived in prose with no
	// backticks, so a changed row is a failure, cleared by reviewing it.
	rows, inv := miniFixture(t, nil)
	changed := strings.Replace(miniMD, "A length, usually", "A length (1 to 128 now), usually", 1)
	newRows, err := ParseRows(changed)
	if err != nil {
		t.Fatal(err)
	}
	p := inv.Validate(newRows)
	if !hasProblem(p, "network:ipv6_pd", "changed since it was reviewed", "reviewed: "+newRows[2].Hash) {
		t.Fatalf("a changed row must fail and print the hash to set: %v", p)
	}
	// Control: the unchanged rows stay green, and reviewing clears it.
	if len(p) != 1 {
		t.Errorf("only the changed row should fail, got %v", p)
	}
	inv.Options["network:ipv6_pd"].Reviewed = newRows[2].Hash
	if p := inv.Validate(newRows); len(p) != 0 {
		t.Errorf("setting reviewed to the new hash should clear it: %v", p)
	}
	_ = rows
}

func TestInventory_UnknownYAMLFieldIsAnError(t *testing.T) {
	_, err := ParseInventory([]byte("options: {}\nalias_groups: []\nenv: {ipv6: [], routes: []}\nmystery: 1\n"))
	if err == nil {
		t.Fatal("an unknown top-level field must be an error")
	}
	_, err = ParseInventory([]byte("options:\n  \"network:x\":\n    reviewed: a\n    valeus: []\n"))
	if err == nil {
		t.Fatal("a misspelt field must be an error")
	}
}

func TestInventory_SettingsHaveNoModePathAndOptionsDo(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, "mode_path: n/a", "mode_path: per-mode")
	})
	if p := inv.Validate(rows); !hasProblem(p, "LOG_LEVEL", "mode_path must be n/a") {
		t.Fatalf("a setting with a mode_path must fail: %v", p)
	}
	rows, inv = miniFixture(t, func(s string) string {
		return mustReplace(t, s, "mode_path: per-mode\n    values:\n      - {v: \"false\"", "mode_path: n/a\n    values:\n      - {v: \"false\"")
	})
	if p := inv.Validate(rows); !hasProblem(p, "skip_routes", "n/a is for plugin settings only") {
		t.Fatalf("an option with mode_path n/a must fail: %v", p)
	}
}

func TestInventory_SharedModePathNeedsACodeRef(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `reviewed: "@@network:ipv6_pd@@"
    families: ["ipv6", "routes"]
    mode_path: per-mode`, `reviewed: "@@network:ipv6_pd@@"
    families: ["ipv6", "routes"]
    mode_path: shared`)
	})
	if p := inv.Validate(rows); !hasProblem(p, "ipv6_pd", "needs a code_ref") {
		t.Fatalf("shared without a code_ref must fail: %v", p)
	}
	inv.Options["network:ipv6_pd"].CodeRef = "pkg/plugin/join.go:Join"
	if p := inv.Validate(rows); hasProblem(p, "ipv6_pd") {
		t.Fatalf("a file:func code_ref should pass: %v", p)
	}
}

func TestInventory_ModesCellMustNameModes(t *testing.T) {
	md := strings.Replace(miniMD, "bridge, macvlan", "bridge, vxlan", 1)
	rows, err := ParseRows(md)
	if err != nil {
		t.Fatal(err)
	}
	_, inv := miniFixture(t, nil)
	if p := inv.Validate(rows); !hasProblem(p, "vxlan", "not a mode") {
		t.Fatalf("an unknown mode in the modes cell must fail: %v", p)
	}
}

func TestInventory_TwoRowsMayNotShareAVariantName(t *testing.T) {
	rows, inv := miniFixture(t, nil)
	inv.Options["network:ipv6_pd"].ID = "skip_routes"
	if p := inv.Validate(rows); !hasProblem(p, "share the variant name") {
		t.Fatalf("two entries with one variant name must fail: %v", p)
	}
}

func TestInventory_TokenKindIsCheckedAgainstTheDocsRow(t *testing.T) {
	addExample := func(md string) string {
		return mustReplace(t, md, "A boolean, ", "A boolean (a prefix such as `192.0.2.7/24` is refused), ")
	}
	anchor := `      - {v: "true", class: allowed}
`
	with := func(extra string) func(string) string {
		return func(s string) string {
			return mustReplace(t, s, `      - {v: "false", class: default}
`+anchor, `      - {v: "false", class: default}
`+anchor+extra)
		}
	}
	// A row with no token of the kind at all: the docs carry no example.
	rows0, inv0 := miniFixture(t, with(`      - {v: "x", class: refused, no_token: true, token_kind: ipv4-prefix-length}
`))
	if p := inv0.Validate(rows0); !hasProblem(p, "carries no token of that kind") {
		t.Errorf("a kind with no token in the row must fail: %v", p)
	}
	for _, c := range []struct {
		name, value, want string
	}{
		{"unknown kind", `      - {v: "192.0.2.7/24", class: refused, no_token: true, token_kind: ipv9}`, "not one of the known kinds"},
		{"kind without no_token", `      - {v: "192.0.2.7/24", class: refused, token_kind: ipv4-prefix-length}`, "must carry no_token"},
	} {
		rows, inv := miniFixtureMD(t, addExample, with(c.value+"\n"))
		if p := inv.Validate(rows); !hasProblem(p, c.want) {
			t.Errorf("%s: want a problem containing %q, got %v", c.name, c.want, p)
		}
	}
	// The kind must not let a token be claimed twice.
	rows, inv := miniFixtureMD(t, addExample, with(`      - {v: "192.0.2.7/24", class: refused, no_token: true, token_kind: ipv4-prefix-length}
`))
	inv.Options["network:skip_routes"].NotValues = append(inv.Options["network:skip_routes"].NotValues, "192.0.2.7/24")
	if p := inv.Validate(rows); len(p) == 0 {
		t.Error("a token both claimed by a kind and parked in not_values must fail")
	}
}

func TestInventory_RefusesWithAndPartnerBelongToAllowedValues(t *testing.T) {
	rows, inv := miniFixture(t, func(s string) string {
		return mustReplace(t, s, `{v: "64", class: allowed}`, `{v: "64", class: refused, refuses_with: ["skip_routes=true"]}`)
	})
	if p := inv.Validate(rows); !hasProblem(p, `value "64"`, "refused on its own") {
		t.Errorf("refuses_with on a refused value must fail: %v", p)
	}
	rows, inv = miniFixture(t, func(s string) string {
		return mustReplace(t, s, `{v: "off", class: default}`, `{v: "off", class: default, partner: true}`)
	})
	if p := inv.Validate(rows); !hasProblem(p, `value "off"`, "partner") {
		t.Errorf("a partner default must fail: %v", p)
	}
}

func TestInventory_RefusedModesMustBeARealPartialRefusal(t *testing.T) {
	validate := func(edit func(string) string) []string {
		rows, inv := miniFixture(t, edit)
		return inv.Validate(rows)
	}
	for _, c := range []struct{ name, repl, want string }{
		{"a mode the value does not apply in", `{v: "64", class: allowed, refused_modes: ["ipvlan"]}`, "where the row does not apply it"},
		{"a mode that is not a mode", `{v: "64", class: allowed, refused_modes: ["bogus"]}`, "where the row does not apply it"},
		{"every mode of the value", `{v: "64", class: allowed, refused_modes: ["bridge", "macvlan"]}`, "refused in every mode"},
		{"a mode listed twice", `{v: "64", class: allowed, refused_modes: ["macvlan", "macvlan"]}`, "twice"},
	} {
		p := validate(func(s string) string { return mustReplace(t, s, `{v: "64", class: allowed}`, c.repl) })
		if !hasProblem(p, c.want) {
			t.Errorf("%s: want a problem containing %q, got %v", c.name, c.want, p)
		}
	}
	p := validate(func(s string) string {
		return mustReplace(t, s, `{v: "off", class: default}`, `{v: "off", class: default, refused_modes: ["ipvlan"]}`)
	})
	if !hasProblem(p, "allowed or boundary") {
		t.Errorf("the default value cannot be refused in a mode: %v", p)
	}
	// Control: a partial refusal in a mode the value applies in is valid.
	if p := validate(func(s string) string {
		return mustReplace(t, s, `{v: "slaac", class: allowed}`, `{v: "slaac", class: allowed, refused_modes: ["ipvlan"]}`)
	}); len(p) != 0 {
		t.Errorf("a partial refusal must validate: %v", p)
	}
}
