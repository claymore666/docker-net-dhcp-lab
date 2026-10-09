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

// Homes and statuses of a placement (issue #35).
const (
	HomeUnit        = "unit"
	HomeIntegration = "integration"
	HomeLab         = "lab"

	StatusCovered = "covered"
	StatusGap     = "gap"
	StatusNA      = "na"
)

// Placement says where a set of variants is tested, or why it is not.
// Exactly one placement must match each variant.
type Placement struct {
	Match  []string `yaml:"match"`
	Home   string   `yaml:"home"`
	Status string   `yaml:"status"`
	// Ref is a plugin test (file:TestName, looked up in tests.txt) or a
	// lab scenario name (looked up in the catalog).
	Ref string `yaml:"ref,omitempty"`
	// Assert is the line of the test that reads the variant's effect.
	Assert string `yaml:"assert,omitempty"`
	// Points lists the timing points the ref reads: start, settled.
	Points  []string `yaml:"points,omitempty"`
	StartNA string   `yaml:"start_na,omitempty"`
	Reason  string   `yaml:"reason,omitempty"`
	Issue   string   `yaml:"issue,omitempty"`
	Also    []string `yaml:"also,omitempty"`
}

// PlacementFile is data/placements.yaml.
type PlacementFile struct {
	Placements []Placement `yaml:"placements"`
}

// LoadPlacements reads path strictly.
func LoadPlacements(path string) ([]Placement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePlacements(data)
}

// ParsePlacements decodes placements YAML strictly; an unknown field is
// an error.
func ParsePlacements(data []byte) ([]Placement, error) {
	var f PlacementFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("placements: %w", err)
	}
	return f.Placements, nil
}

// LabScenario is what the check needs of a catalog entry.
type LabScenario struct {
	Name  string
	Needs []string
}

// Input is everything CheckVariants judges a matrix against.
type Input struct {
	Variants   []Variant
	Placements []Placement
	// Tests is the set of file:TestName refs of tests.txt.
	Tests map[string]bool
	Lab   []LabScenario
	// Undeclared are capabilities no adapter declares yet; a lab
	// scenario needing one is not running anywhere.
	Undeclared map[string]bool
	// ModePath maps a variant option name to shared or per-mode.
	ModePath map[string]string
}

// Result is CheckVariants' report.
type Result struct {
	Problems []string
	// Counts is home/status to the number of variants placed there.
	Counts map[string]int
	Total  int
}

var issueRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+#[0-9]+$`)

type compiled struct {
	p        Placement
	idx      int
	patterns []ID
	ok       bool
}

func (in Input) refKind(ref string) string {
	switch {
	case strings.HasPrefix(ref, "pkg/plugin/"):
		return HomeUnit
	case strings.HasPrefix(ref, "test/integration/"):
		return HomeIntegration
	}
	for _, s := range in.Lab {
		if s.Name == ref {
			return HomeLab
		}
	}
	return ""
}

// CheckVariants judges variants against placements, the plugin's tests
// and the lab catalog. It returns one problem per item, sorted.
func CheckVariants(in Input) Result {
	res := Result{Counts: map[string]int{}, Total: len(in.Variants)}
	add := func(f string, a ...any) { res.Problems = append(res.Problems, fmt.Sprintf(f, a...)) }
	cs := make([]compiled, len(in.Placements))
	for i, p := range in.Placements {
		c := compiled{p: p, idx: i, ok: true}
		label := placementLabel(p, i)
		if len(p.Match) == 0 {
			add("%s: has no match patterns", label)
			c.ok = false
		}
		for _, m := range p.Match {
			id, err := ParseID(m)
			if err != nil {
				// An ErrGlob already names the pattern and the rule.
				add("%s: %v", label, err)
				c.ok = false
				continue
			}
			if id.Mode == "*" {
				for _, opt := range id.Options() {
					if in.ModePath[opt] != "shared" {
						add("%s: pattern %q has a mode glob, which is legal only where the option's mode_path is shared (%s is %q)", label, m, opt, in.ModePath[opt])
						c.ok = false
					}
				}
			}
			c.patterns = append(c.patterns, id)
		}
		res.Problems = append(res.Problems, in.checkPlacement(p, label)...)
		cs[i] = c
	}
	matched := make([]int, len(cs))
	for _, v := range in.Variants {
		id, err := ParseID(v.ID)
		if err != nil {
			add("variant %s does not parse: %v", v.ID, err)
			continue
		}
		var hits []int
		for _, c := range cs {
			if !c.ok {
				continue
			}
			for _, pat := range c.patterns {
				if pat.Matches(id) {
					hits = append(hits, c.idx)
					matched[c.idx]++
					break
				}
			}
		}
		switch len(hits) {
		case 0:
			add("variant %s has no placement", v.ID)
		case 1:
			p := in.Placements[hits[0]]
			res.Counts[in.countKey(p)]++
			res.Problems = append(res.Problems, in.checkVariantPlacement(v, id, p, placementLabel(p, hits[0]))...)
		default:
			names := make([]string, len(hits))
			for i, h := range hits {
				names[i] = placementLabel(in.Placements[h], h)
			}
			add("variant %s has %d placements: %s", v.ID, len(hits), strings.Join(names, "; "))
		}
	}
	for i, c := range cs {
		if c.ok && matched[i] == 0 {
			add("%s: matches no variant", placementLabel(c.p, i))
		}
	}
	sort.Strings(res.Problems)
	return res
}

func placementLabel(p Placement, i int) string {
	first := ""
	if len(p.Match) > 0 {
		first = p.Match[0]
	}
	return fmt.Sprintf("placement #%d (%s)", i+1, first)
}

// countKey is the report row of a placement. A lab ref that cannot run
// is a gap whatever the file says.
func (in Input) countKey(p Placement) string {
	status := p.Status
	if status == StatusCovered && in.labGated(p.Ref) != "" {
		status = StatusGap
	}
	return p.Home + "/" + status
}

// labGated names the undeclared capability a lab ref needs, or "".
func (in Input) labGated(ref string) string {
	for _, s := range in.Lab {
		if s.Name != ref {
			continue
		}
		for _, n := range s.Needs {
			if in.Undeclared[n] {
				return n
			}
		}
	}
	return ""
}

// checkPlacement holds the rules that depend on the placement alone.
func (in Input) checkPlacement(p Placement, label string) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, label+": "+fmt.Sprintf(f, a...)) }
	switch p.Home {
	case HomeUnit, HomeIntegration, HomeLab:
	default:
		add("home %q is not unit, integration or lab", p.Home)
	}
	switch p.Status {
	case StatusCovered:
		if p.Ref == "" {
			add("covered without a ref")
			break
		}
		kind := in.refKind(p.Ref)
		switch {
		case kind == "":
			add("ref %q is neither a lab scenario of the catalog nor a plugin test path", p.Ref)
		case kind != p.Home:
			add("ref %q is a %s ref but the placement's home is %s", p.Ref, kind, p.Home)
		case kind != HomeLab && !in.Tests[p.Ref]:
			add("ref %q is not in tests.txt of the pinned tag", p.Ref)
		}
		if n := in.labGated(p.Ref); n != "" {
			add("ref %q needs capability %q, which no adapter declares: it runs nowhere, so this is a gap, not coverage", p.Ref, n)
		}
		for _, a := range p.Also {
			if in.refKind(a) == "" {
				add("also %q is neither a lab scenario nor a plugin test path", a)
			} else if in.refKind(a) != HomeLab && !in.Tests[a] {
				add("also %q is not in tests.txt of the pinned tag", a)
			}
		}
		if p.Assert == "" {
			add("covered without an assert line")
		}
		for _, pt := range p.Points {
			if pt != "start" && pt != "settled" {
				add("point %q is not start or settled", pt)
			}
		}
	case StatusGap:
		if !issueRE.MatchString(p.Issue) {
			add("gap needs an issue of the form owner/repo#N, has %q", p.Issue)
		}
	case StatusNA:
		if strings.TrimSpace(p.Reason) == "" {
			add("na needs a reason")
		}
	default:
		add("status %q is not covered, gap or na", p.Status)
	}
	return out
}

// checkVariantPlacement holds the rules that need the variant too.
func (in Input) checkVariantPlacement(v Variant, id ID, p Placement, label string) []string {
	var out []string
	if p.Status != StatusCovered {
		return nil
	}
	if v.Runtime && !containsStr(p.Points, "start") && strings.TrimSpace(p.StartNA) == "" {
		out = append(out, fmt.Sprintf("%s: runtime variant %s needs a start point or a start_na reason", label, v.ID))
	}
	if v.Runtime && !containsStr(p.Points, "settled") {
		out = append(out, fmt.Sprintf("%s: runtime variant %s needs a settled point", label, v.ID))
	}
	if v.Runtime && id.Kind == KindAlias && p.Home == HomeUnit {
		hostRef := false
		for _, a := range p.Also {
			switch in.refKind(a) {
			case HomeIntegration:
				hostRef = hostRef || in.Tests[a]
			case HomeLab:
				// A scenario that needs a capability nothing declares
				// runs nowhere, so it does not reach Join.
				hostRef = hostRef || in.labGated(a) == ""
			}
		}
		if !hostRef {
			out = append(out, fmt.Sprintf("%s: runtime alias %s is placed on a unit ref only; two spellings equal at decode can differ at Join (#1125), so it needs an integration or lab ref", label, v.ID))
		}
	}
	return out
}
