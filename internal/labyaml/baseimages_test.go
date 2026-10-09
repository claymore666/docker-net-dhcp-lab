package labyaml

import (
	"strings"
	"testing"
)

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

func TestAptSourcesFixOnlyForTheArchivedDebian11Image(t *testing.T) {
	for name, bi := range baseImages {
		if name != "debian-11-generic-amd64" && bi.AptSourcesFix != "" {
			t.Errorf("%s: AptSourcesFix = %q; only debian-11 left the regular mirrors (issue #27)", name, bi.AptSourcesFix)
		}
	}
	bi, err := LookupBaseImage("debian-11-generic-amd64")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"http://archive.debian.org/debian bullseye main'",
		"http://archive.debian.org/debian bullseye-updates main'",
		"http://archive.debian.org/debian-security bullseye-security main'",
		"> /etc/apt/sources.list",
	} {
		if !strings.Contains(bi.AptSourcesFix, want) {
			t.Errorf("debian-11 AptSourcesFix lacks %q: %s", want, bi.AptSourcesFix)
		}
	}
	for _, bad := range []string{"deb.debian.org", "security.debian.org", "deb-src"} {
		if strings.Contains(bi.AptSourcesFix, bad) {
			t.Errorf("debian-11 AptSourcesFix names %q; the point is to leave it", bad)
		}
	}
}

func TestAptSourcesFixSurvivesRendererSed(t *testing.T) {
	// the shell renderer substitutes with sed s#..#..#g and the value sits
	// in a YAML block scalar: '#', '&', a backslash or a newline break it
	for name, bi := range baseImages {
		if strings.ContainsAny(bi.AptSourcesFix, "#&\\\n") {
			t.Errorf("%s: AptSourcesFix has a character the sed substitution cannot carry: %q", name, bi.AptSourcesFix)
		}
	}
}
