package coverage

import (
	"strings"
	"testing"
)

func withNetRow(row string) string {
	return strings.Replace(miniMD, "| `skip_routes` | all | `false` | upstream | A boolean, `true` or `false`. |\n",
		"| `skip_routes` | all | `false` | upstream | A boolean, `true` or `false`. |\n"+row+"\n", 1)
}

func TestParseRows_NamelessRowIsAnError(t *testing.T) {
	// The old parser stopped the table here and dropped every row after it.
	_, err := ParseRows(withNetRow("| not-an-option | all | `x` | v1 | text |"))
	if err == nil || !strings.Contains(err.Error(), "without a backticked option name") {
		t.Fatalf("a nameless table row must fail, got %v", err)
	}
}

func TestParseRows_SixthColumnIsAnError(t *testing.T) {
	_, err := ParseRows(withNetRow("| `extra` | all | `x` | v1 | text | surprise |"))
	if err == nil || !strings.Contains(err.Error(), "6 cells") {
		t.Fatalf("a row with a sixth cell must fail, got %v", err)
	}
	_, err = ParseRows(withNetRow("| `short` | all | `x` | v1 |"))
	if err == nil || !strings.Contains(err.Error(), "4 cells") {
		t.Fatalf("a short row must fail, got %v", err)
	}
}

func TestParseRows_OddBackticksIsAnError(t *testing.T) {
	_, err := ParseRows(withNetRow("| `odd` | all | `x` | v1 | a `broken span |"))
	if err == nil || !strings.Contains(err.Error(), "odd number of backticks") {
		t.Fatalf("an unpaired backtick must fail, got %v", err)
	}
}

func TestParseRows_TokensAreDistinctAndOrdered(t *testing.T) {
	rows, err := ParseRows(withNetRow("| `dup` | all | `x` | v1 | `b` then `a` then `b` and `a=1`. |"))
	if err != nil {
		t.Fatal(err)
	}
	var dup Row
	for _, r := range rows {
		if r.Name == "dup" {
			dup = r
		}
	}
	if got := strings.Join(dup.Tokens, "|"); got != "b|a|a=1" {
		t.Errorf("tokens = %q, want b|a|a=1", got)
	}
}

func TestParseRows_HashFollowsTheCellsNotTheWhitespace(t *testing.T) {
	a, err := ParseRows(miniMD)
	if err != nil {
		t.Fatal(err)
	}
	spaced := strings.Replace(miniMD, "A length, usually", "A  length,   usually", 1)
	b, err := ParseRows(spaced)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ParseRows(strings.Replace(miniMD, "A length, usually", "A longer length, usually", 1))
	if err != nil {
		t.Fatal(err)
	}
	idx := -1
	for i, r := range a {
		if r.Name == "ipv6_pd" {
			idx = i
		}
	}
	if a[idx].Hash != b[idx].Hash {
		t.Errorf("collapsing whitespace must not change the hash")
	}
	if a[idx].Hash == changed[idx].Hash {
		t.Errorf("changing a word must change the hash")
	}
	for i := range a {
		if i != idx && a[i].Hash != changed[i].Hash {
			t.Errorf("row %s changed though only ipv6_pd was edited", a[i].Key())
		}
	}
}

func TestParseRows_KeysAreNamespaced(t *testing.T) {
	rows, err := ParseRows(miniMD)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"network:mode", "network:ipv6_mode", "network:ipv6_pd", "network:skip_routes", "endpoint:ip", "setting:LOG_LEVEL"}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d", len(rows), len(want))
	}
	for i, r := range rows {
		if r.Key() != want[i] {
			t.Errorf("row %d key %s, want %s", i, r.Key(), want[i])
		}
	}
}
