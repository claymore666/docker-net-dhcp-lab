package coverage

import (
	"fmt"
	"regexp"
	"strings"
)

// Variant kinds (issue #35). The ID grammar is the one the design fixes:
//
//	single    opt=value@mode    (mode omitted for plugin settings)
//	refused   opt=!value
//	outofmode opt@!mode
//	alias     alias:A~B[@mode]  (A, B are spellings: terms joined by +)
//	pair      pair:a=x+b=y@mode
//	env       env:opt=value@mode#E1
const (
	KindSingle    = "single"
	KindRefused   = "refused"
	KindOutOfMode = "outofmode"
	KindAlias     = "alias"
	KindPair      = "pair"
	KindEnv       = "env"
)

// Term is one option written with one value.
type Term struct {
	Opt string
	Val string
}

func (t Term) String() string { return t.Opt + "=" + t.Val }

// ID is a parsed variant ID, or a placement pattern: a pattern is an ID
// whose value, mode or profile may be "*".
type ID struct {
	Kind    string
	A       []Term // single, refused, env: one term; pair: two; alias: first spelling
	B       []Term // alias: second spelling
	Mode    string
	Profile string
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func termsString(ts []Term) string {
	parts := make([]string, len(ts))
	for i, t := range ts {
		parts[i] = t.String()
	}
	return strings.Join(parts, "+")
}

// String renders the canonical ID text.
func (id ID) String() string {
	at := ""
	if id.Mode != "" {
		at = "@" + id.Mode
	}
	switch id.Kind {
	case KindAlias:
		return "alias:" + termsString(id.A) + "~" + termsString(id.B) + at
	case KindPair:
		return "pair:" + termsString(id.A) + at
	case KindEnv:
		return "env:" + termsString(id.A) + at + "#" + id.Profile
	case KindOutOfMode:
		return id.A[0].Opt + "@!" + id.Mode
	default:
		return termsString(id.A) + at
	}
}

// ErrGlob is returned for a pattern that wildcards an option name.
type ErrGlob struct{ Pattern string }

func (e ErrGlob) Error() string {
	return fmt.Sprintf("pattern %q wildcards an option name; a glob may only stand for a value, a mode or a profile", e.Pattern)
}

func parseTerm(s, whole string) (Term, error) {
	opt, val, ok := strings.Cut(s, "=")
	if !ok || opt == "" || val == "" {
		return Term{}, fmt.Errorf("term %q in %q is not opt=value", s, whole)
	}
	if strings.Contains(opt, "*") {
		return Term{}, ErrGlob{whole}
	}
	if !nameRE.MatchString(opt) {
		return Term{}, fmt.Errorf("option name %q in %q has characters an ID cannot carry", opt, whole)
	}
	return Term{opt, val}, nil
}

func parseTerms(s, whole string, n int) ([]Term, error) {
	parts := strings.Split(s, "+")
	if n > 0 && len(parts) != n {
		return nil, fmt.Errorf("%q wants %d terms, has %d", whole, n, len(parts))
	}
	out := make([]Term, len(parts))
	for i, p := range parts {
		t, err := parseTerm(p, whole)
		if err != nil {
			return nil, err
		}
		out[i] = t
	}
	return out, nil
}

// ParseID parses a variant ID or a placement pattern.
func ParseID(s string) (ID, error) {
	whole := s
	var id ID
	switch {
	case strings.HasPrefix(s, "alias:"):
		id.Kind = KindAlias
		body := strings.TrimPrefix(s, "alias:")
		if i := strings.LastIndex(body, "@"); i >= 0 {
			body, id.Mode = body[:i], body[i+1:]
		}
		a, b, ok := strings.Cut(body, "~")
		if !ok {
			return id, fmt.Errorf("alias %q has no ~", whole)
		}
		var err error
		if id.A, err = parseTerms(a, whole, 0); err != nil {
			return id, err
		}
		if id.B, err = parseTerms(b, whole, 0); err != nil {
			return id, err
		}
	case strings.HasPrefix(s, "pair:"):
		id.Kind = KindPair
		body := strings.TrimPrefix(s, "pair:")
		i := strings.LastIndex(body, "@")
		if i < 0 {
			return id, fmt.Errorf("pair %q has no @mode", whole)
		}
		body, id.Mode = body[:i], body[i+1:]
		var err error
		if id.A, err = parseTerms(body, whole, 2); err != nil {
			return id, err
		}
	case strings.HasPrefix(s, "env:"):
		id.Kind = KindEnv
		body := strings.TrimPrefix(s, "env:")
		i := strings.LastIndex(body, "#")
		if i < 0 {
			return id, fmt.Errorf("env %q has no #profile", whole)
		}
		body, id.Profile = body[:i], body[i+1:]
		j := strings.LastIndex(body, "@")
		if j < 0 {
			return id, fmt.Errorf("env %q has no @mode", whole)
		}
		body, id.Mode = body[:j], body[j+1:]
		var err error
		if id.A, err = parseTerms(body, whole, 1); err != nil {
			return id, err
		}
	case strings.Contains(s, "@!"):
		id.Kind = KindOutOfMode
		opt, mode, _ := strings.Cut(s, "@!")
		if strings.Contains(opt, "*") {
			return id, ErrGlob{whole}
		}
		if !nameRE.MatchString(opt) || mode == "" {
			return id, fmt.Errorf("out-of-mode %q is not opt@!mode", whole)
		}
		id.A, id.Mode = []Term{{Opt: opt}}, mode
	default:
		body := s
		if i := strings.LastIndex(body, "@"); i >= 0 {
			body, id.Mode = body[:i], body[i+1:]
		}
		t, err := parseTerm(body, whole)
		if err != nil {
			return id, err
		}
		id.A = []Term{t}
		id.Kind = KindSingle
		if strings.HasPrefix(t.Val, "!") {
			id.Kind = KindRefused
			if id.Mode != "" {
				return id, fmt.Errorf("refused variant %q carries no mode", whole)
			}
		}
	}
	if id.Profile != "" && id.Profile != "*" && !profileRE.MatchString(id.Profile) {
		return id, fmt.Errorf("profile %q in %q is not E1..E4", id.Profile, whole)
	}
	return id, nil
}

var profileRE = regexp.MustCompile(`^E[1-4]$`)

func termsMatch(pattern, v []Term) bool {
	if len(pattern) != len(v) {
		return false
	}
	for i := range pattern {
		if pattern[i].Opt != v[i].Opt {
			return false
		}
		refused := strings.HasPrefix(v[i].Val, "!")
		switch {
		case pattern[i].Val == v[i].Val:
		case pattern[i].Val == "*" && !refused:
		case pattern[i].Val == "!*" && refused:
		default:
			return false
		}
	}
	return true
}

// Matches reports whether pattern (an ID that may hold "*") covers v.
// A "*" never stands for an option name; ParseID refuses that.
func (p ID) Matches(v ID) bool {
	if p.Kind != v.Kind {
		return false
	}
	if p.Mode != v.Mode && p.Mode != "*" {
		return false
	}
	if p.Profile != v.Profile && p.Profile != "*" {
		return false
	}
	if p.Kind == KindOutOfMode {
		return p.A[0].Opt == v.A[0].Opt
	}
	return termsMatch(p.A, v.A) && termsMatch(p.B, v.B)
}

// Options lists the option names an ID mentions, in order.
func (id ID) Options() []string {
	var out []string
	for _, t := range append(append([]Term{}, id.A...), id.B...) {
		out = append(out, t.Opt)
	}
	return out
}
