package labyaml

import (
	"slices"
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

// Every registered image names a kind and seed the shell dispatches on,
// and only a built image has no URL (#9).
func TestBaseImageKindsAndSeedsAreKnown(t *testing.T) {
	for name, bi := range baseImages {
		if !slices.Contains(ImageKinds, bi.Kind) || !slices.Contains(SeedKinds, bi.Seed) {
			t.Errorf("%s: kind %q seed %q, want one of %v and %v", name, bi.Kind, bi.Seed, ImageKinds, SeedKinds)
		}
		if (bi.Kind == "built") != (bi.URL == "") {
			t.Errorf("%s: kind %q with URL %q", name, bi.Kind, bi.URL)
		}
		if bi.ChecksumURL != "" && bi.Kind != "archive" {
			t.Errorf("%s: an upstream checksum URL on a %s image", name, bi.Kind)
		}
		if !slices.Contains(Firmwares, bi.Firmware) {
			t.Errorf("%s: firmware %q, want one of %q", name, bi.Firmware, Firmwares)
		}
	}
}

// CHR 7.24.5 ships a raw disk in a zip with no sums file beside it, is
// seeded through its guest agent and boots under SeaBIOS only (M3, #9).
func TestCHRImageIsAnAgentSeededArchiveUnderSeaBIOS(t *testing.T) {
	bi, err := LookupBaseImage("chr-7.24.5")
	if err != nil {
		t.Fatal(err)
	}
	want := BaseImage{Name: "chr-7.24.5", URL: "https://download.mikrotik.com/routeros/7.24.5/chr-7.24.5.img.zip",
		OSVariant: "linux2020", Kind: "archive", Seed: "qga", Firmware: "bios"}
	if bi != want {
		t.Errorf("chr-7.24.5 = %+v, want %+v", bi, want)
	}
	for name, bi := range baseImages {
		if name != "chr-7.24.5" && bi.Firmware != "" {
			t.Errorf("%s: firmware %q; only CHR needs SeaBIOS", name, bi.Firmware)
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

// The three images every cell ran on before #9 stay plain qcow2 cloud
// images seeded by cloud-init.
func TestTodaysImagesAreQcow2CloudInit(t *testing.T) {
	for _, name := range []string{"debian-13-generic-amd64", "debian-11-generic-amd64", "ubuntu-24.04-server-cloudimg-amd64"} {
		if bi := baseImages[name]; bi.Kind != "qcow2" || bi.Seed != "cloud-init" || bi.ChecksumURL != "" {
			t.Errorf("%s = %+v", name, bi)
		}
	}
}
