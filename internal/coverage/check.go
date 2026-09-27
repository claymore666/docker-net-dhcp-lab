package coverage

import "sort"

// Result is one coverage run's summary (issue #4): every option
// docs/reference.md's tables name, whether it maps to a scenario this
// lab actually runs, or carries a recorded reason it does not yet.
type Result struct {
	Total    int
	Covered  int
	Reasoned int
	// Unmapped is every option that fails the check: absent from
	// Mapping entirely, or present with neither a Scenario nor a
	// Reason. Sorted, for a deterministic report.
	Unmapped []string
}

// Check compares options (ParseOptions' output) against Mapping. It is
// the "fails, with a clear message, when an option maps to no scenario
// and has no recorded reason" rule issue #4 asks for -- the caller
// decides what "fails" means (labctl coverage's non-zero exit); this
// function only classifies.
func Check(options []string) Result {
	var r Result
	seen := map[string]bool{}
	for _, opt := range options {
		if seen[opt] {
			// docs/reference.md listing the same option twice under one
			// table is a docs bug, not a coverage gap; counted once.
			continue
		}
		seen[opt] = true
		r.Total++
		entry, ok := Mapping[opt]
		switch {
		case !ok:
			r.Unmapped = append(r.Unmapped, opt+" (not in coverage mapping at all)")
		case entry.Scenario != "":
			r.Covered++
		case entry.Reason != "":
			r.Reasoned++
		default:
			r.Unmapped = append(r.Unmapped, opt+" (mapping entry carries neither a scenario nor a reason)")
		}
	}
	sort.Strings(r.Unmapped)
	return r
}
