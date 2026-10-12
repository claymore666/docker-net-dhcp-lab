// Package coverage checks docs/reference.md's option tables, in the
// docker-net-dhcp plugin repo, against the lab's own record of which
// option a scenario actually exercises (issue #4). It never runs
// anything: FetchURL is the only network call in this package, and a
// caller that already has the file locally (a test, or a pinned copy)
// never needs it at all.
package coverage

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// RawURL is the raw-GitHub location of docs/reference.md at ref (a tag
// such as v2.2.2, or a branch), in the plugin repo this lab tests.
func RawURL(ref string) string {
	return fmt.Sprintf("https://raw.githubusercontent.com/claymore666/docker-net-dhcp/%s/docs/reference.md", ref)
}

// FetchURL reads url's whole body as text. Kept this small and this
// separate from ParseRows so a test can call ParseRows directly
// on a fixture string, with no HTTP round trip in it at all.
func FetchURL(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("fetch %s: read body: %w", url, err)
	}
	return string(body), nil
}

// Row is one option or setting row of docs/reference.md (issue #35):
// the cells the matrix generator reads, the backticked tokens of the
// description, and a hash of the whole row, for the reviewed-row check.
type Row struct {
	Table   string // network, endpoint or setting
	Name    string
	Modes   string // network table only: the modes cell as written
	Default string // network and setting tables: the default cell as written
	Since   string // network table only
	Text    string // the last cell: description or meaning
	Tokens  []string
	Hash    string
}

// Key is the namespaced name Mapping uses, e.g. network:mode.
func (r Row) Key() string { return r.Table + ":" + r.Name }

// optionRowRE matches a markdown table row whose first cell is a
// backtick-quoted option/setting name, e.g. "| `mode` | n/a | ...".
// The separator row ("| ------ | ----- |") and the header row ("|
// option | modes | ...", no backticks) both fail this on purpose.
var optionRowRE = regexp.MustCompile("^\\| `([A-Za-z0-9_.]+)` \\|")

var tokenRE = regexp.MustCompile("`([^`]+)`")

// tables is every option/setting table docs/reference.md publishes,
// each under its own "## " heading, with the namespace this package
// qualifies an option name with (the three tables do not share one
// option namespace -- a network-level `ip` would collide with the
// per-endpoint one if they did), that table's own exact header row and
// its column count. The header pins ParseRows to the one real table
// under each heading: a heading's prose goes on to show worked examples
// in its own two-column tables too (host_ifname's container-name-to-
// link-name table is one), and only the row shape with the right header
// is a documented option, never an example. The "At a glance" summary
// table earlier in the file restates the same network-level option names
// and is deliberately not a fourth source (issue #4).
var tables = []struct {
	heading string
	table   string
	header  string
	cols    int
}{
	{"## Driver options (network-level)", "network", "| option | modes | default | since | description |", 5},
	{"## Driver options (per-endpoint)", "endpoint", "| option | description |", 2},
	{"## Plugin settings", "setting", "| name | default | meaning |", 3},
}

// ParseRows extracts every option/setting row reference.md's three
// tables carry. Each table must contribute its own header row: a
// vanished or renamed heading, or a header row that gained or lost a
// column, fails outright, naming the heading. Inside a captured table a
// line that starts with "|" but has no backticked name, or whose cell
// count differs from the header's, is an error and never a silent end
// of the table: the old parser dropped every row after such a line
// (issue #35, defeat 1).
func ParseRows(md string) ([]Row, error) {
	var out []Row
	headerSeen := make([]bool, len(tables))
	sc := bufio.NewScanner(strings.NewReader(md))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	capturing := false
	tableIdx := -1
	wantHeader := false
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), " \t\r")
		if strings.HasPrefix(line, "## ") {
			tableIdx, capturing, wantHeader = -1, false, false
			for i, t := range tables {
				if line == t.heading {
					tableIdx, wantHeader = i, true
				}
			}
			continue
		}
		if tableIdx < 0 {
			continue
		}
		if !capturing {
			if wantHeader && line == tables[tableIdx].header {
				capturing = true
				headerSeen[tableIdx] = true
			}
			continue
		}
		if !strings.HasPrefix(line, "|") {
			// A table ends at its first non-table line; later tables under
			// the same heading (worked examples) are deliberately ignored.
			capturing, wantHeader = false, false
			continue
		}
		if strings.HasPrefix(line, "| ---") {
			continue
		}
		t := tables[tableIdx]
		m := optionRowRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("parse options: line %d under %q is a table row without a backticked option name: %.60s", lineNo, t.heading, line)
		}
		if strings.Count(line, "`")%2 != 0 {
			return nil, fmt.Errorf("parse options: line %d (%s) has an odd number of backticks, so its tokens cannot be read", lineNo, m[1])
		}
		cells := splitCells(line)
		if len(cells) != t.cols {
			return nil, fmt.Errorf("parse options: line %d (%s) has %d cells, the table under %q has %d", lineNo, m[1], len(cells), t.heading, t.cols)
		}
		r := Row{Table: t.table, Name: m[1], Text: cells[len(cells)-1]}
		switch t.table {
		case "network":
			r.Modes, r.Default, r.Since = cells[1], cells[2], cells[3]
		case "setting":
			r.Default = cells[1]
		}
		r.Tokens = tokensOf(r.Text)
		r.Hash = rowHash(cells)
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse options: %w", err)
	}
	var missing []string
	for i, seen := range headerSeen {
		if !seen {
			missing = append(missing, tables[i].heading)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("parse options: found no header row under %v; the heading or its header row may have changed", missing)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parse options: found no option rows under any of the %d known heading(s); docs/reference.md's headings may have changed", len(tables))
	}
	return out, nil
}

// splitCells splits a table row on "|" outside backtick spans and
// returns the trimmed cells without the outer pipes.
func splitCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	var cells []string
	var cur strings.Builder
	inCode := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '`':
			inCode = !inCode
			cur.WriteByte(c)
		case c == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteByte('|')
			i++
		case c == '|' && !inCode:
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

// tokensOf returns the distinct backticked tokens of text in order of
// first appearance.
func tokensOf(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range tokenRE.FindAllStringSubmatch(text, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// rowHash fingerprints a row's cells with whitespace collapsed, so the
// inventory can record which version of the row a human reviewed.
func rowHash(cells []string) string {
	h := sha256.New()
	for _, c := range cells {
		h.Write([]byte(strings.Join(strings.Fields(c), " ")))
		h.Write([]byte{0x1f})
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
