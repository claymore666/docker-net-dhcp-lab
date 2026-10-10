package coverage

import (
	"fmt"
	"sort"
	"strings"
)

// Profiles are the environment profiles of the design: a strength-2
// covering array over H (host routes), P (advertised prefixes) and D
// (DHCPv6 offered). E3 and E4 are the two #1125 triples.
var Profiles = []Profile{
	{"E1", "kernel", 1, true},
	{"E2", "kernel", 2, false},
	{"E3", "network manager", 1, false},
	{"E4", "network manager", 2, true},
}

// Profile is one row of the environment table.
type Profile struct {
	Name     string
	Host     string
	Prefixes int
	Offered  bool
}

// Variant is one generated row of the matrix.
type Variant struct {
	ID       string
	Kind     string
	Mode     string
	Families []string
	// Runtime variants are read at the container's start and once
	// settled; the others are decided when the network is created.
	Runtime bool
}

// Points is the timing column: what a placement must read.
func (v Variant) Points() string {
	if v.Runtime {
		return "start,settled"
	}
	return "create"
}

// optInfo is one inventory entry joined with its docs row.
type optInfo struct {
	name   string
	row    Row
	spec   *OptionSpec
	modes  []string
	isMode bool
}

func (o optInfo) valueModes(v ValueSpec) []string {
	if o.row.Table == "setting" {
		return []string{""}
	}
	return ValueModes(o.spec, v, o.modes)
}

func (o optInfo) value(s string) (ValueSpec, bool) {
	for _, v := range o.spec.Values {
		if v.V == s {
			return v, true
		}
	}
	return ValueSpec{}, false
}

func (o optInfo) defaultValue() ValueSpec {
	for _, v := range o.spec.Values {
		if v.Class == ClassDefault {
			return v
		}
	}
	return ValueSpec{}
}

// partnerValue is the value a docs-named partner pair uses: the value
// marked partner, else the first allowed or boundary value.
func (o optInfo) partnerValue() (ValueSpec, bool) {
	for _, v := range o.spec.Values {
		if v.Partner {
			return v, true
		}
	}
	for _, v := range o.spec.Values {
		if v.Class == ClassAllowed || v.Class == ClassBoundary {
			return v, true
		}
	}
	return ValueSpec{}, false
}

func interModes(a, b []string) []string {
	var out []string
	for _, m := range a {
		if containsStr(b, m) {
			out = append(out, m)
		}
	}
	return out
}

type builder struct {
	byID map[string]*Variant
	err  []string
	// refused holds the pair IDs the docs say are refused at network
	// creation; they are decided at create, not read at a start.
	refused map[string]bool
	// spelled holds the pair IDs that are another spelling of an alias
	// group member; the alias variant already stands for them.
	spelled map[string]bool
	// modeRefused (#35) holds "opt=value@mode" for each value the docs refuse
	// in one mode; a variant naming it there is decided at create.
	modeRefused map[string]bool
}

// createOnly (#35) reports whether the docs refuse the variant at network
// creation: a refused pair, or a term whose value is refused in the mode.
func (b *builder) createOnly(id ID) bool {
	if id.Kind == KindPair && b.refused[id.String()] {
		return true
	}
	if id.Mode == "" {
		return false
	}
	for _, t := range id.A {
		if b.modeRefused[t.Opt+"="+t.Val+"@"+id.Mode] {
			return true
		}
	}
	return false
}

func (b *builder) add(id ID, runtime bool, family string) {
	s := id.String()
	if id.Kind == KindPair && b.spelled[s] {
		return
	}
	create := b.createOnly(id)
	if create {
		runtime = false
	}
	v := b.byID[s]
	if v == nil {
		v = &Variant{ID: s, Kind: id.Kind, Mode: id.Mode, Runtime: runtime}
		b.byID[s] = v
	} else if create {
		// A variant an earlier loop added as runtime is still decided at create.
		v.Runtime = false
	}
	if family != "" && !containsStr(v.Families, family) {
		v.Families = append(v.Families, family)
	}
}

// Generate expands the docs rows and the inventory into the matrix. It
// refuses to run on an inventory that does not account for every row.
func Generate(rows []Row, inv *Inventory) ([]Variant, error) {
	if p := inv.Validate(rows); len(p) > 0 {
		return nil, fmt.Errorf("inventory does not match the docs:\n  %s", strings.Join(p, "\n  "))
	}
	opts := map[string]optInfo{}
	var order []string
	for _, r := range rows {
		spec := inv.Options[r.Key()]
		modes, isMode, err := RowModes(r)
		if err != nil {
			return nil, err
		}
		o := optInfo{name: spec.name(r), row: r, spec: spec, modes: modes, isMode: isMode}
		opts[o.name] = o
		order = append(order, o.name)
	}
	b := &builder{byID: map[string]*Variant{}, refused: map[string]bool{}, spelled: map[string]bool{}, modeRefused: map[string]bool{}}
	for _, n := range order {
		for _, v := range opts[n].spec.Values {
			for _, m := range v.RefusedModes {
				b.modeRefused[n+"="+v.V+"@"+m] = true
			}
		}
	}
	if err := b.spellings(inv); err != nil {
		return nil, err
	}
	genSingles(b, opts, order)
	if err := genAliases(b, inv, opts, order); err != nil {
		return nil, err
	}
	genRefusedPairs(b, opts, order)
	genFamilyPairs(b, opts, order)
	genNamedPairs(b, opts, order)
	if err := genEnv(b, inv, opts); err != nil {
		return nil, err
	}
	if len(b.err) > 0 {
		return nil, fmt.Errorf("generate:\n  %s", strings.Join(b.err, "\n  "))
	}
	out := make([]Variant, 0, len(b.byID))
	for _, v := range b.byID {
		sort.Strings(v.Families)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func genSingles(b *builder, opts map[string]optInfo, order []string) {
	for _, n := range order {
		o := opts[n]
		for _, v := range o.spec.Values {
			if v.Class == ClassRefused {
				b.add(ID{Kind: KindRefused, A: []Term{{n, "!" + v.V}}}, false, "")
				continue
			}
			for _, m := range o.valueModes(v) {
				b.add(ID{Kind: KindSingle, A: []Term{{n, v.V}}, Mode: m}, true, "")
			}
		}
		if o.row.Table != "network" || o.isMode {
			continue
		}
		for _, m := range AllModes {
			if !containsStr(o.modes, m) {
				b.add(ID{Kind: KindOutOfMode, A: []Term{{Opt: n}}, Mode: m}, false, "")
			}
		}
	}
}

func (b *builder) checkTerms(group string, ts []Term, opts map[string]optInfo, free bool) {
	for _, t := range ts {
		o, ok := opts[t.Opt]
		if !ok {
			b.err = append(b.err, fmt.Sprintf("alias %s names option %q, which is not an option of the docs", group, t.Opt))
			continue
		}
		if _, known := o.value(t.Val); !known && t.Val != "unset" && !free {
			b.err = append(b.err, fmt.Sprintf("alias %s: %s is not a value of %s", group, t, t.Opt))
		}
	}
}

func genAliases(b *builder, inv *Inventory, opts map[string]optInfo, order []string) error {
	for _, n := range order {
		o := opts[n]
		if o.row.Table != "network" {
			continue
		}
		unset := []Term{{n, "unset"}}
		b.add(ID{Kind: KindAlias, A: []Term{{n, "empty"}}, B: unset}, false, "")
		if o.spec.Boolean {
			b.add(ID{Kind: KindAlias, A: []Term{{n, "1"}}, B: []Term{{n, "true"}}}, false, "")
			b.add(ID{Kind: KindAlias, A: []Term{{n, "0"}}, B: []Term{{n, "false"}}}, false, "")
		}
		if d := o.defaultValue(); !o.spec.NoWrittenDefault && d.V != "unset" {
			b.add(ID{Kind: KindAlias, A: []Term{{n, d.V}}, B: unset}, false, "")
		}
	}
	for _, g := range inv.Aliases {
		first, err := parseTerms(g.Members[0], g.Members[0], 0)
		if err != nil {
			return err
		}
		b.checkTerms(g.Name, first, opts, g.Free)
		modes := g.Modes
		if len(modes) == 0 {
			modes = []string{""}
		}
		for _, m := range g.Members[1:] {
			other, err := parseTerms(m, m, 0)
			if err != nil {
				return err
			}
			b.checkTerms(g.Name, other, opts, g.Free)
			for _, mode := range modes {
				b.add(ID{Kind: KindAlias, A: first, B: other, Mode: mode}, g.Runtime, "")
			}
		}
	}
	return nil
}

func familyMembers(opts map[string]optInfo, order []string) map[string][]string {
	fam := map[string][]string{}
	for _, n := range order {
		for _, f := range opts[n].spec.Families {
			fam[f] = append(fam[f], n)
		}
	}
	for f := range fam {
		sort.Strings(fam[f])
	}
	return fam
}

func nonDefault(o optInfo) []ValueSpec {
	var out []ValueSpec
	for _, v := range o.spec.Values {
		if v.Class == ClassAllowed || v.Class == ClassBoundary {
			out = append(out, v)
		}
	}
	return out
}

// pairIDs are the pair variants of two values, one per mode both allow.
func pairIDs(a, c optInfo, va, vc ValueSpec) []ID {
	if a.name > c.name {
		a, c, va, vc = c, a, vc, va
	}
	var out []ID
	for _, m := range interModes(a.valueModes(va), c.valueModes(vc)) {
		out = append(out, ID{Kind: KindPair, A: []Term{{a.name, va.V}, {c.name, vc.V}}, Mode: m})
	}
	return out
}

func addPair(b *builder, a, c optInfo, va, vc ValueSpec, family string) {
	for _, id := range pairIDs(a, c, va, vc) {
		b.add(id, true, family)
	}
}

// spellings records the pair IDs that an alias group's two-term members
// spell, so a pair is not generated for a configuration an alias row
// already stands for.
func (b *builder) spellings(inv *Inventory) error {
	for _, g := range inv.Aliases {
		for _, m := range g.Members {
			ts, err := parseTerms(m, m, 0)
			if err != nil {
				return err
			}
			if len(ts) != 2 {
				continue
			}
			if ts[0].Opt > ts[1].Opt {
				ts[0], ts[1] = ts[1], ts[0]
			}
			for _, mode := range g.Modes {
				b.spelled[ID{Kind: KindPair, A: ts, Mode: mode}.String()] = true
			}
		}
	}
	return nil
}

// genRefusedPairs adds the pairs the docs say are refused at network
// creation, each decided when the network is created (refuses_with).
func genRefusedPairs(b *builder, opts map[string]optInfo, order []string) {
	for _, n := range order {
		a := opts[n]
		for _, va := range a.spec.Values {
			for _, w := range va.RefusesWith {
				opt, val, ok := strings.Cut(w, "=")
				c, known := opts[opt]
				if !ok || !known {
					b.err = append(b.err, fmt.Sprintf("%s=%s refuses_with %q, which is not an option=value of the docs", n, va.V, w))
					continue
				}
				vc, known := c.value(val)
				if !known || vc.Class == ClassRefused {
					b.err = append(b.err, fmt.Sprintf("%s=%s refuses_with %q, which is not a non-refused value of %s", n, va.V, w, opt))
					continue
				}
				for _, id := range pairIDs(a, c, va, vc) {
					b.refused[id.String()] = true
					b.add(id, false, "refused")
				}
			}
		}
	}
}

func genFamilyPairs(b *builder, opts map[string]optInfo, order []string) {
	fam := familyMembers(opts, order)
	names := make([]string, 0, len(fam))
	for f := range fam {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		ms := fam[f]
		for i := range ms {
			for j := i + 1; j < len(ms); j++ {
				a, c := opts[ms[i]], opts[ms[j]]
				for _, va := range nonDefault(a) {
					for _, vc := range nonDefault(c) {
						addPair(b, a, c, va, vc, f)
					}
				}
			}
		}
	}
}

// genNamedPairs adds the pair a docs row names: a backticked token that
// is another option's name, or `other=value`, pairs the row's option
// with that option. A pair with a default on either side is no separate
// row, and two options of one family are already paired there.
func genNamedPairs(b *builder, opts map[string]optInfo, order []string) {
	for _, n := range order {
		a := opts[n]
		if a.row.Table != "network" || a.isMode {
			continue
		}
		av, ok := a.partnerValue()
		if !ok {
			continue
		}
		for _, tok := range a.row.Tokens {
			opt, val, hasVal := strings.Cut(strings.TrimPrefix(tok, "-o "), "=")
			c, ok := opts[opt]
			if !ok || c.name == n || c.row.Table != "network" || c.isMode || strings.ContainsAny(val, " \t") {
				continue
			}
			var cv ValueSpec
			if hasVal {
				if cv, ok = c.value(val); !ok {
					continue
				}
			} else if cv, ok = c.partnerValue(); !ok {
				continue
			}
			if cv.Class != ClassAllowed && cv.Class != ClassBoundary {
				continue
			}
			addPair(b, a, c, av, cv, "named")
		}
	}
}

func genEnv(b *builder, inv *Inventory, opts map[string]optInfo) error {
	emit := func(spellings []string, profiles []Profile) error {
		for _, s := range spellings {
			ts, err := parseTerms(s, s, 1)
			if err != nil {
				return err
			}
			b.checkTerms("env", ts, opts, false)
			for _, m := range AllModes {
				for _, p := range profiles {
					b.add(ID{Kind: KindEnv, A: ts, Mode: m, Profile: p.Name}, true, "env")
				}
			}
		}
		return nil
	}
	if err := emit(inv.Env.IPv6, Profiles); err != nil {
		return err
	}
	// The routes family takes H only: kernel (E1) and network manager (E3).
	return emit(inv.Env.Routes, []Profile{Profiles[0], Profiles[2]})
}

// FormatMatrix renders the checked-in matrix.tsv.
func FormatMatrix(vs []Variant) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# variants: %d\n", len(vs))
	sb.WriteString("# id\tkind\tmode\tfamilies\tpoints\n")
	for _, v := range vs {
		fmt.Fprintf(&sb, "%s\t%s\t%s\t%s\t%s\n", v.ID, v.Kind, v.Mode, strings.Join(v.Families, ","), v.Points())
	}
	return sb.String()
}

// Counts is a per-kind tally for the report.
func Counts(vs []Variant) map[string]int {
	m := map[string]int{}
	for _, v := range vs {
		m[v.Kind]++
	}
	return m
}
