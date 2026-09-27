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
}

var baseImages = map[string]BaseImage{
	"debian-13-generic-amd64": {
		Name:      "debian-13-generic-amd64",
		URL:       "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2",
		Distro:    "debian",
		Suite:     "trixie",
		OSVariant: "debian13",
	},
	// The plugin's oldest supported engine target (issue #8): an older
	// distro so docker-ce's own version pin below resolves against a repo
	// that still carries it -- download.docker.com drops old package
	// builds from a suite's newer pool once it moves on.
	"debian-11-generic-amd64": {
		Name:      "debian-11-generic-amd64",
		URL:       "https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2",
		Distro:    "debian",
		Suite:     "bullseye",
		OSVariant: "debian11",
	},
	"ubuntu-24.04-server-cloudimg-amd64": {
		Name:      "ubuntu-24.04-server-cloudimg-amd64",
		URL:       "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img",
		Distro:    "ubuntu",
		Suite:     "noble",
		OSVariant: "ubuntu24.04",
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
