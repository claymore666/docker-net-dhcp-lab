package coverage

import (
	"embed"
	"io/fs"
)

// dataFS holds the hand-kept inventory and placements and the
// generated matrix and pinned releases (issue #35).
//
//go:embed data
var dataFS embed.FS

// Data returns the data directory as a file system rooted at it.
func Data() fs.FS {
	sub, err := fs.Sub(dataFS, "data")
	if err != nil {
		panic(err)
	}
	return sub
}

// ParseInventoryFS and friends read the embedded copies.
func inventoryFrom(fsys fs.FS) (*Inventory, error) {
	b, err := fs.ReadFile(fsys, "inventory.yaml")
	if err != nil {
		return nil, err
	}
	return ParseInventory(b)
}

func placementsFrom(fsys fs.FS) ([]Placement, error) {
	b, err := fs.ReadFile(fsys, "placements.yaml")
	if err != nil {
		return nil, err
	}
	return ParsePlacements(b)
}

// LoadData reads inventory and placements from fsys.
func LoadData(fsys fs.FS) (*Inventory, []Placement, error) {
	inv, err := inventoryFrom(fsys)
	if err != nil {
		return nil, nil, err
	}
	pl, err := placementsFrom(fsys)
	if err != nil {
		return nil, nil, err
	}
	return inv, pl, nil
}

// ModePaths maps each variant option name to its mode_path.
func (inv *Inventory) ModePaths(rows []Row) map[string]string {
	m := map[string]string{}
	for _, r := range rows {
		if o := inv.Options[r.Key()]; o != nil {
			m[o.name(r)] = o.ModePath
		}
	}
	return m
}
