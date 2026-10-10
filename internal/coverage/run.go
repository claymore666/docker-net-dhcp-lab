package coverage

import (
	"fmt"
	"io/fs"
	"strings"
)

// Loaded is a pinned release joined with the hand-kept data.
type Loaded struct {
	Pinned     *Pinned
	Rows       []Row
	Inventory  *Inventory
	Placements []Placement
	Variants   []Variant
}

// LoadPinnedMatrix parses the pinned reference and generates the matrix
// from the inventory.
func LoadPinnedMatrix(fsys fs.FS, tag string) (*Loaded, error) {
	p, err := LoadPinned(fsys, tag)
	if err != nil {
		return nil, err
	}
	rows, err := ParseRows(p.Reference)
	if err != nil {
		return nil, fmt.Errorf("pinned/%s/reference.md: %w", tag, err)
	}
	inv, pl, err := LoadData(fsys)
	if err != nil {
		return nil, err
	}
	vs, err := Generate(rows, inv)
	if err != nil {
		return nil, err
	}
	return &Loaded{Pinned: p, Rows: rows, Inventory: inv, Placements: pl, Variants: vs}, nil
}

// MatrixDiff compares the checked-in matrix.tsv with a fresh one and
// returns "" when they are equal, else a one-line account.
func MatrixDiff(fsys fs.FS, fresh []Variant) string {
	got, err := fs.ReadFile(fsys, "matrix.tsv")
	if err != nil {
		return fmt.Sprintf("matrix.tsv cannot be read: %v", err)
	}
	want := FormatMatrix(fresh)
	if string(got) == want {
		return ""
	}
	gl, wl := strings.Split(string(got), "\n"), strings.Split(want, "\n")
	have := map[string]bool{}
	for _, l := range gl {
		have[l] = true
	}
	var added, removed []string
	wantSet := map[string]bool{}
	for _, l := range wl {
		wantSet[l] = true
		if !have[l] {
			added = append(added, l)
		}
	}
	for _, l := range gl {
		if !wantSet[l] {
			removed = append(removed, l)
		}
	}
	first := func(xs []string) string {
		if len(xs) == 0 {
			return "-"
		}
		return strings.SplitN(xs[0], "\t", 2)[0]
	}
	return fmt.Sprintf("matrix.tsv is stale: %d line(s) would be added (first %s), %d removed (first %s); run labctl coverage --pinned TAG --regen", len(added), first(added), len(removed), first(removed))
}
