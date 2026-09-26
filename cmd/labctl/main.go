// labctl is the lab's Go control plane: it owns lab.yaml and hands
// resolved, already-validated values to the shell scripts that do the
// provisioning. It never touches the network or libvirt itself.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "validate":
		cmdValidate(os.Args[2:])
	case "resolve":
		cmdResolve(os.Args[2:])
	case "leases":
		cmdLeases(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: labctl validate <lab.yaml>")
	fmt.Fprintln(os.Stderr, "       labctl resolve <lab.yaml> <cell-name>")
	fmt.Fprintln(os.Stderr, "       labctl leases <source-type> <mgmt-ip> <known-hosts>")
	os.Exit(2)
}

// cmdLeases prints one source's lease table as raw text, read through the
// adapter, over the same per-cell known_hosts and key up-cell.sh already
// established (issue #2). This is the measured evidence path: whatever it
// prints came from the source's own interface, never from the plugin.
func cmdLeases(args []string) {
	if len(args) != 3 {
		usage()
	}
	sourceType, mgmtIP, knownHosts := args[0], args[1], args[2]
	runner := sourceadapter.SSHRunner{
		Host:       mgmtIP,
		User:       "lab",
		KeyPath:    os.ExpandEnv("$HOME/.ssh/id_ed25519_lab"),
		KnownHosts: knownHosts,
	}
	var a sourceadapter.Adapter
	switch sourceType {
	case "kea":
		a = &sourceadapter.KeaAdapter{Runner: runner}
	case "isc-dhcp":
		a = &sourceadapter.ISCDHCPAdapter{Runner: runner}
	case "dnsmasq":
		a = &sourceadapter.DnsmasqAdapter{Runner: runner}
	default:
		fmt.Fprintln(os.Stderr, "labctl leases: unknown source type", sourceType)
		os.Exit(2)
	}
	leases, err := a.Leases(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl leases:", err)
		os.Exit(1)
	}
	for _, l := range leases {
		fmt.Printf("%s %s %s\n", l.MAC, l.Address, l.Hostname)
	}
}

func cmdValidate(args []string) {
	if len(args) != 1 {
		usage()
	}
	if _, err := labyaml.Load(args[0]); err != nil {
		fmt.Fprintln(os.Stderr, "labctl validate:", err)
		os.Exit(1)
	}
	fmt.Println("ok")
}

func cmdResolve(args []string) {
	if len(args) != 2 {
		usage()
	}
	cfg, err := labyaml.Load(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve:", err)
		os.Exit(1)
	}
	cell, err := cfg.CellByName(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve:", err)
		os.Exit(1)
	}
	out := struct {
		Management labyaml.Management `json:"management"`
		ULAPrefix  string             `json:"ula_prefix"`
		Cell       *labyaml.Cell      `json:"cell"`
	}{cfg.Management, cfg.ULAPrefix, cell}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve: encode:", err)
		os.Exit(1)
	}
}
