package labyaml

import "testing"

func TestLookupBaseImageKnownNamesResolve(t *testing.T) {
	for _, name := range []string{
		"debian-13-generic-amd64",
		"debian-11-generic-amd64",
		"ubuntu-24.04-server-cloudimg-amd64",
	} {
		bi, err := LookupBaseImage(name)
		if err != nil {
			t.Fatalf("LookupBaseImage(%q): %v", name, err)
		}
		if bi.URL == "" || bi.Distro == "" || bi.Suite == "" || bi.OSVariant == "" {
			t.Fatalf("LookupBaseImage(%q) = %+v; every field must be set", name, bi)
		}
	}
}

func TestLookupBaseImageUnknownNameFails(t *testing.T) {
	if _, err := LookupBaseImage("not-a-registered-image"); err == nil {
		t.Fatal("LookupBaseImage on an unregistered name: got nil error, want one naming the value")
	}
}
