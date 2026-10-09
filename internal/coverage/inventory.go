package coverage

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Value classes (issue #35).
const (
	ClassDefault  = "default"
	ClassAllowed  = "allowed"
	ClassBoundary = "boundary"
	ClassRefused  = "refused"
)

// AllModes is the lab's three attachment modes, in matrix order.
var AllModes = []string{"bridge", "macvlan", "ipvlan"}

// Families an option can belong to; all pairs inside a family are
// generated (design, "Matrix size").
var knownFamilies = map[string]bool{"ipv6": true, "routes": true, "identity": true, "conflict": true}

// ValueSpec is one value of one option. V is the spelling written in
// the -o flag, or "unset" for the option omitted. The row tokens it
// accounts for are V itself (unless NoToken) plus Tokens.
type ValueSpec struct {
	V       string   `yaml:"v"`
	Class   string   `yaml:"class"`
	Modes   []string `yaml:"modes,omitempty"`
	NoToken bool     `yaml:"no_token,omitempty"`
	Tokens  []string `yaml:"tokens,omitempty"`
	// Matches is the docs default cell this value stands for when the
	// cell is not just the value in backticks, e.g. "from DHCP".
	Matches string `yaml:"matches,omitempty"`
	// Partner marks the value a docs-named partner pair uses for this
	// option; without one the first non-default value is used.
	Partner bool `yaml:"partner,omitempty"`
	// RefusesWith lists opt=value spellings the docs say are refused at
	// network creation beside this value. Each becomes a pair variant
	// decided when the network is created, not read at a container's start.
	RefusesWith []string `yaml:"refuses_with,omitempty"`
	// RefusedModes (#35) lists the modes in which the docs refuse this value
	// at network creation although it is accepted in the others. Every
	// variant that names the value in such a mode is decided at create.
	RefusedModes []string `yaml:"refused_modes,omitempty"`
	// TokenKind accounts for the row's backticked tokens of one named
	// shape (see tokenKinds), for a refused example the inventory should
	// not spell out. It needs no_token.
	TokenKind string `yaml:"token_kind,omitempty"`
}

// tokenKinds are the shapes a value can claim row tokens by. The
// patterns hold no address, so the inventory carries no literal either.
var tokenKinds = map[string]*regexp.Regexp{
	"ipv4-prefix-length": regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$`),
}

// OptionSpec is the hand-kept record of one docs row.
type OptionSpec struct {
	// ID is the name variant IDs use when the row name is too long.
	ID string `yaml:"id,omitempty"`
	// Reviewed is the row hash the entry was last checked against; a
	// docs row that changed since fails the check until it is updated.
	Reviewed         string      `yaml:"reviewed"`
	Boolean          bool        `yaml:"boolean,omitempty"`
	NoWrittenDefault bool        `yaml:"no_written_default,omitempty"`
	Families         []string    `yaml:"families,omitempty"`
	ModePath         string      `yaml:"mode_path"`
	CodeRef          string      `yaml:"code_ref,omitempty"`
	Values           []ValueSpec `yaml:"values"`
	NotValues        []string    `yaml:"not_values,omitempty"`
}

// AliasGroup is a hand-kept set of spellings the docs say mean the same
// thing: every member after the first is generated against the first.
type AliasGroup struct {
	Name    string   `yaml:"name"`
	Runtime bool     `yaml:"runtime,omitempty"`
	Modes   []string `yaml:"modes,omitempty"`
	// Free allows spellings whose value is not a value of the option.
	Free     bool     `yaml:"free,omitempty"`
	External []string `yaml:"external,omitempty"`
	Members  []string `yaml:"members"`
}

// EnvSpec names the spellings the environment profiles are crossed with.
type EnvSpec struct {
	IPv6   []string `yaml:"ipv6"`
	Routes []string `yaml:"routes"`
}

// Inventory is data/inventory.yaml.
type Inventory struct {
	Options map[string]*OptionSpec `yaml:"options"`
	Aliases []AliasGroup           `yaml:"alias_groups"`
	Env     EnvSpec                `yaml:"env"`
}

// LoadInventory reads path strictly: an unknown field is an error.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseInventory(data)
}

// ParseInventory decodes inventory YAML strictly.
func ParseInventory(data []byte) (*Inventory, error) {
	var inv Inventory
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	return &inv, nil
}

// Name returns the variant-ID name of the row.
func (o *OptionSpec) name(r Row) string {
	if o.ID != "" {
		return o.ID
	}
	return r.Name
}

var codeRefRE = regexp.MustCompile(`^[^:\s]+:[A-Za-z_][A-Za-z0-9_.]*$`)

// valueOK reports whether s can sit inside a variant ID.
func valueOK(s string) bool {
	return s != "" && s != "*" && !strings.HasPrefix(s, "!") && !strings.ContainsAny(s, "@+~#=* \t")
}

// plainDefault is the default cell as the inventory spells it: the cell
// itself, or the text of a lone backtick span.
func plainDefault(cell string) string {
	cell = strings.TrimSpace(cell)
	if toks := tokenRE.FindAllStringSubmatch(cell, -1); len(toks) == 1 && toks[0][0] == cell {
		return toks[0][1]
	}
	return cell
}

// RowModes resolves the modes cell of a row. ModeIsValue is true for
// the `mode` option itself, whose "modes" cell is n/a.
func RowModes(r Row) (modes []string, modeIsValue bool, err error) {
	switch r.Table {
	case "setting":
		return nil, false, nil
	case "endpoint":
		return AllModes, false, nil
	}
	switch strings.TrimSpace(r.Modes) {
	case "all":
		return AllModes, false, nil
	case "n/a":
		return AllModes, true, nil
	}
	for _, m := range strings.Split(r.Modes, ",") {
		m = strings.TrimSpace(m)
		ok := false
		for _, a := range AllModes {
			ok = ok || a == m
		}
		if !ok {
			return nil, false, fmt.Errorf("%s: modes cell %q names %q, which is not a mode", r.Key(), r.Modes, m)
		}
		modes = append(modes, m)
	}
	return modes, false, nil
}

// ValueModes is the modes a value applies in.
func ValueModes(o *OptionSpec, v ValueSpec, optModes []string) []string {
	if len(v.Modes) > 0 {
		return v.Modes
	}
	return optModes
}

// Validate checks the docs rows against the inventory and returns one
// problem per item, sorted. An empty slice means the inventory accounts
// for every row, every token, every default and every review hash.
func (inv *Inventory) Validate(rows []Row) []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	seenRow := map[string]bool{}
	ids := map[string]string{}
	for _, r := range rows {
		key := r.Key()
		seenRow[key] = true
		o := inv.Options[key]
		if o == nil {
			add("docs row %s is not in inventory.yaml", key)
			continue
		}
		if id := o.name(r); ids[id] != "" {
			add("%s and %s share the variant name %q", ids[id], key, id)
		} else {
			ids[id] = key
		}
		if o.Reviewed != r.Hash {
			add("docs row %s changed since it was reviewed (inventory says %q, the row hashes to %s): re-read the row, update the entry, then set reviewed: %s", key, o.Reviewed, r.Hash, r.Hash)
		}
		p = append(p, o.validateAgainst(r)...)
	}
	for key := range inv.Options {
		if !seenRow[key] {
			add("inventory.yaml has %s, which is not a row of the docs", key)
		}
	}
	p = append(p, inv.validateAliases()...)
	sort.Strings(p)
	return p
}

func (o *OptionSpec) validateAgainst(r Row) []string {
	var p []string
	key := r.Key()
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf("%s: "+f, append([]any{key}, a...)...)) }
	optModes, modeIsValue, err := RowModes(r)
	if err != nil {
		add("%v", err)
	}
	if r.Table == "setting" {
		if o.ModePath != "n/a" {
			add("a plugin setting has no mode: mode_path must be n/a, has %q", o.ModePath)
		}
	} else if o.ModePath == "n/a" {
		add("mode_path n/a is for plugin settings only")
	}
	switch o.ModePath {
	case "n/a":
	case "shared":
		if !codeRefRE.MatchString(o.CodeRef) {
			add("mode_path shared needs a code_ref of the form file:func, has %q", o.CodeRef)
		}
	case "per-mode":
		if o.CodeRef != "" {
			add("mode_path per-mode carries no code_ref")
		}
	default:
		add("mode_path must be shared or per-mode, has %q", o.ModePath)
	}
	for _, f := range o.Families {
		if !knownFamilies[f] {
			add("unknown family %q", f)
		}
	}
	accounted := map[string]string{}
	claim := func(tok, who string) {
		if prev, dup := accounted[tok]; dup {
			add("token `%s` is classed twice (%s and %s)", tok, prev, who)
			return
		}
		accounted[tok] = who
	}
	rowTok := map[string]bool{}
	for _, t := range r.Tokens {
		rowTok[t] = true
	}
	nDefault := 0
	vals := map[string]bool{}
	want := plainDefault(r.Default)
	defaultFound := r.Table == "endpoint"
	for _, v := range o.Values {
		switch v.Class {
		case ClassDefault, ClassAllowed, ClassBoundary, ClassRefused:
		default:
			add("value %q has class %q, not default, allowed, boundary or refused", v.V, v.Class)
		}
		if !valueOK(v.V) {
			add("value %q cannot sit inside a variant ID (empty, *, leading !, or one of @ + ~ # = space)", v.V)
		}
		if vals[v.V] {
			add("value %q is listed twice", v.V)
		}
		vals[v.V] = true
		if v.Class == ClassDefault {
			nDefault++
			if v.V == want || v.Matches == want {
				defaultFound = true
			}
		}
		if v.Matches != "" && v.Class != ClassDefault {
			add("value %q has matches but is not the default", v.V)
		}
		for _, m := range v.Modes {
			if !containsStr(optModes, m) {
				add("value %q lists mode %q, which the row does not allow", v.V, m)
			}
		}
		if !v.NoToken {
			claim(v.V, "value "+v.V)
		}
		if v.TokenKind != "" {
			re := tokenKinds[v.TokenKind]
			switch {
			case re == nil:
				add("value %q has token_kind %q, which is not one of the known kinds", v.V, v.TokenKind)
			case !v.NoToken:
				add("value %q has a token_kind, so it must carry no_token", v.V)
			default:
				found := false
				for _, t := range r.Tokens {
					if re.MatchString(t) {
						found = true
						claim(t, "value "+v.V+" (token_kind "+v.TokenKind+")")
					}
				}
				if !found {
					add("value %q has token_kind %q, but the docs row carries no token of that kind", v.V, v.TokenKind)
				}
			}
		}
		if v.Class == ClassRefused && len(v.RefusesWith) > 0 {
			add("value %q is refused on its own, so it cannot also be refused beside another option", v.V)
		}
		if len(v.RefusedModes) > 0 {
			applies := ValueModes(o, v, optModes)
			switch {
			case v.Class != ClassAllowed && v.Class != ClassBoundary:
				add("value %q has refused_modes, so it must be an allowed or boundary value", v.V)
			case len(v.RefusedModes) >= len(applies):
				add("value %q is refused in every mode it applies in: that is a refused value, not refused_modes", v.V)
			}
			seen := map[string]bool{}
			for _, m := range v.RefusedModes {
				if !containsStr(applies, m) {
					add("value %q is refused in mode %q, where the row does not apply it", v.V, m)
				}
				if seen[m] {
					add("value %q lists refused mode %q twice", v.V, m)
				}
				seen[m] = true
			}
		}
		if v.Partner && (v.Class == ClassDefault || v.Class == ClassRefused) {
			add("value %q is the partner of a named pair, so it cannot be the default or a refused value", v.V)
		}
		for _, t := range v.Tokens {
			claim(t, "value "+v.V)
		}
	}
	if modeIsValue && len(o.Values) == 0 {
		add("the mode option needs its values")
	}
	if nDefault != 1 {
		add("needs exactly one default-class value, has %d", nDefault)
	}
	if !defaultFound {
		add("the docs default %q is not among the values (as v or matches of the default value)", want)
	}
	if o.Boolean && !(vals["true"] && vals["false"]) {
		add("a boolean option lists true and false")
	}
	name := o.name(r)
	for _, t := range o.NotValues {
		claim(t, "not_values")
		if t == want {
			add("not_values holds the parsed default %q, which is a value", t)
		}
		if opt, val, ok := strings.Cut(strings.TrimPrefix(t, "-o "), "="); ok && (opt == name || opt == r.Name) && val != "" && !strings.ContainsAny(val, " \t") {
			add("not_values holds `%s`, the option's own opt=value token, which is a value spelling", t)
		}
	}
	for tok, who := range accounted {
		if !rowTok[tok] {
			add("%s names the token `%s`, which the docs row does not carry", who, tok)
		}
	}
	for _, t := range r.Tokens {
		if _, ok := accounted[t]; !ok {
			add("token `%s` of the docs row is classed neither as a value nor in not_values", t)
		}
	}
	return p
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func (inv *Inventory) validateAliases() []string {
	var p []string
	names := map[string]bool{}
	for _, g := range inv.Aliases {
		add := func(f string, a ...any) {
			p = append(p, fmt.Sprintf("alias group %s: "+f, append([]any{g.Name}, a...)...))
		}
		if names[g.Name] || g.Name == "" {
			add("name is empty or used twice")
		}
		names[g.Name] = true
		if len(g.Members) < 2 {
			add("needs at least two members")
		}
		for _, m := range g.Modes {
			if m == "" || strings.ContainsAny(m, "@!#~+= ") {
				add("mode %q cannot sit inside an ID", m)
			}
		}
		for _, m := range g.Members {
			ts, err := parseTerms(m, m, 0)
			if err != nil {
				add("%v", err)
				continue
			}
			for _, t := range ts {
				if !valueOK(t.Val) {
					add("member %q has a value that cannot sit inside an ID", m)
				}
			}
		}
	}
	e := inv.Env
	if len(e.IPv6) == 0 || len(e.Routes) == 0 {
		p = append(p, "env needs ipv6 and routes spellings")
	}
	return p
}
