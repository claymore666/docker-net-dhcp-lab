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
// separate from ParseOptions so a test can call ParseOptions directly
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

// optionRowRE matches a markdown table row whose first cell is a
// backtick-quoted option/setting name, e.g. "| `mode` | n/a | ...".
// The separator row ("| ------ | ----- |") and the header row ("|
// option | modes | ...", no backticks) both fail this on purpose.
var optionRowRE = regexp.MustCompile("^\\| `([A-Za-z0-9_.]+)` \\|")

// tables is every option/setting table docs/reference.md publishes,
// each under its own "## " heading, with the namespace prefix this
// package qualifies an option name with (the three tables do not share
// one option namespace -- a network-level `ip` would collide with the
// per-endpoint one if they did) and that table's own exact header row.
// The header pins ParseOptions to the one real table under each
// heading: a heading's prose goes on to show worked examples in its own
// two-column tables too (host_ifname's container-name-to-link-name
// table is one), and only the row shape with the right header is a
// documented option, never an example. The "At a glance" summary table
// earlier in the file restates the same network-level option names and
// is deliberately not a fourth source: parsing it too would just make
// every option's name appear twice in the same result.
var tables = []struct {
	heading string
	prefix  string
	header  string
}{
	{"## Driver options (network-level)", "network:", "| option | modes | default | since | description |"},
	{"## Driver options (per-endpoint)", "endpoint:", "| option | description |"},
	{"## Plugin settings", "setting:", "| name | default | meaning |"},
}

// ParseOptions extracts every option/setting name reference.md's three
// tables carry, qualified by which table it came from. A heading with
// no matching rows contributes nothing rather than failing -- if
// docs/reference.md ever drops a whole section, the option names that
// used to live there simply vanish from the returned list, and Check
// reports them missing from Mapping's coverage the same way it would
// report a single dropped row, never a parse error unrelated to
// coverage itself.
func ParseOptions(md string) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(md))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	// prefix/wantHeader: set on the heading itself, live until that
	// table's header row is seen. capturing/prefix stay live only
	// through that one table's own rows; any table-shaped line seen
	// after capturing has already ended (an example table, further
	// down the same section) is deliberately ignored.
	prefix := ""
	wantHeader := ""
	capturing := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \t\r")
		if h, p, header := matchHeading(line); h {
			prefix, wantHeader, capturing = p, header, false
			continue
		}
		if strings.HasPrefix(line, "## ") {
			prefix, wantHeader, capturing = "", "", false
			continue
		}
		if prefix == "" {
			continue
		}
		if !capturing {
			if line == wantHeader {
				capturing = true
			}
			continue
		}
		if m := optionRowRE.FindStringSubmatch(line); m != nil {
			out = append(out, prefix+m[1])
			continue
		}
		// A row that isn't a separator row ("| --- | --- |", no
		// backticks) ends this table -- the "At a glance" summary and a
		// worked-example table further down the same section must never
		// be read as more rows of the option table itself.
		if !strings.HasPrefix(line, "| ---") {
			capturing = false
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse options: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("parse options: found no option rows under any of the %d known heading(s); docs/reference.md's headings may have changed", len(tables))
	}
	return out, nil
}

// matchHeading reports whether line is exactly one of tables' own
// headings, returning its namespace prefix and expected header row too.
func matchHeading(line string) (bool, string, string) {
	for _, t := range tables {
		if line == t.heading {
			return true, t.prefix, t.header
		}
	}
	return false, "", ""
}
