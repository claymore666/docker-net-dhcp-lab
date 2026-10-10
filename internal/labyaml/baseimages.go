package labyaml

import "fmt"

// BaseImage is the one place that maps a lab.yaml base_image name to
// where its cloud image comes from and how cloud-init and virt-install
// must treat it (issue #8, host axis). Adding a base image means adding
// one row here and one pinned checksum in images/<name>.sha256, never a
// second, hand-kept copy of this table in shell: fetch-base-image.sh,
// up-cell.sh and up-source.sh all read it through `labctl resolve`.
type BaseImage struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Distro and Suite pick download.docker.com's own apt path
	// (https://download.docker.com/linux/<distro> <suite> stable).
	Distro string `json:"distro"` // debian | ubuntu
	Suite  string `json:"suite"`  // trixie, bullseye, noble, ...
	// OSVariant is virt-install's --os-variant value.
	OSVariant string `json:"os_variant"`
	// AptSourcesFix is a one-line shell command that rewrites
	// /etc/apt/sources.list for a release whose pool left the regular
	// mirrors; empty (the default) leaves the image's own sources alone.
	// The docker-host template runs it from bootcmd, which cloud-init
	// executes before package-update-upgrade-install (issue #27).
	AptSourcesFix string `json:"apt_sources_fix"`
	// Kind is how fetch-base-image.sh turns URL into a qcow2 (#9):
	// qcow2 is fetched as is, archive is a .zip/.gz/.bz2 holding a raw
	// disk, built is a build script's output with no URL. ChecksumURL is
	// an archive's upstream sums file, when the vendor publishes one.
	Kind        string `json:"kind"`
	ChecksumURL string `json:"checksum_url,omitempty"`
	// Seed is up-source.sh's seed hook and ready probe: cloud-init, qga
	// (the QEMU guest agent) or baked (the image carries its own seed).
	Seed string `json:"seed"`
	// Firmware is empty for OVMF, up-source.sh's default, or bios for
	// SeaBIOS: OVMF found no boot entry on the CHR 7.24.5 raw image and
	// SeaBIOS booted it (M3, 2026-10-10, lab #9).
	Firmware string `json:"firmware,omitempty"`
}

// archiveAptSourcesFix returns the AptSourcesFix command that points a
// Debian suite and its updates/security pockets at archive.debian.org.
// No '#', '&' or backslash in the result: scripts/render-docker-host-user-data.sh
// substitutes it with sed. check-valid-until=no guards a Release file that
// gains an expiry; none of the three carries one today (issue #27).
func archiveAptSourcesFix(suite string) string {
	const opt = "[check-valid-until=no] http://archive.debian.org/"
	return "{ echo 'deb " + opt + "debian " + suite + " main';" +
		" echo 'deb " + opt + "debian " + suite + "-updates main';" +
		" echo 'deb " + opt + "debian-security " + suite + "-security main'; }" +
		" > /etc/apt/sources.list"
}

// ImageKinds and SeedKinds are the values fetch-base-image.sh and
// up-source.sh dispatch on; any other value is refused there too.
var (
	ImageKinds = []string{"qcow2", "archive", "built"}
	SeedKinds  = []string{"cloud-init", "qga", "baked"}
	Firmwares  = []string{"", "bios"}
)

var baseImages = map[string]BaseImage{
	"debian-13-generic-amd64": {
		Name:      "debian-13-generic-amd64",
		URL:       "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
		Distro:    "debian",
		Suite:     "trixie",
		OSVariant: "debian13",
		Kind:      "qcow2",
		Seed:      "cloud-init",
	},
	// The plugin's oldest supported engine target (issue #27): an older
	// distro so docker-ce's own version pin below resolves against a repo
	// that still carries it -- download.docker.com drops old package
	// builds from a suite's newer pool once it moves on.
	"debian-11-generic-amd64": {
		Name:      "debian-11-generic-amd64",
		URL:       "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2",
		Distro:    "debian",
		Suite:     "bullseye",
		OSVariant: "debian11",
		// Debian 11 left LTS on 2026-08-31: its security pool files 404
		// on the regular mirrors while the Release file is still served
		// (issue #27, measured 2026-10-09).
		AptSourcesFix: archiveAptSourcesFix("bullseye"),
		Kind:          "qcow2",
		Seed:          "cloud-init",
	},
	"ubuntu-24.04-server-cloudimg-amd64": {
		Name:      "ubuntu-24.04-server-cloudimg-amd64",
		URL:       "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
		Distro:    "ubuntu",
		Suite:     "noble",
		OSVariant: "ubuntu24.04",
		Kind:      "qcow2",
		Seed:      "cloud-init",
	},
	// MikroTik CHR, the vendor's stable 7.24.5 raw disk in a zip. No sums
	// file is published beside it (404, DESIGN-910 3.3), so the first
	// fetch pins the archive's sha256 (lab #9). osinfo has no RouterOS.
	"chr-7.24.5": {
		Name:      "chr-7.24.5",
		URL:       "https://download.mikrotik.com/routeros/7.24.5/chr-7.24.5.img.zip",
		OSVariant: "linux2020",
		Kind:      "archive",
		Seed:      "qga",
		Firmware:  "bios",
	},
}

// LookupBaseImage returns name's registered image, or an error naming
// the unregistered value -- labyaml.Validate calls this so a lab.yaml
// typo in base_image fails at `labctl validate`, not partway through a
// bring-up (issue #1's "a check, not a checklist" rule).
func LookupBaseImage(name string) (BaseImage, error) {
	bi, ok := baseImages[name]
	if !ok {
		return BaseImage{}, fmt.Errorf("base image %q is not registered in internal/labyaml/baseimages.go", name)
	}
	return bi, nil
}
