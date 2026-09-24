// labctl is the lab's Go control plane (track file, L10): it owns
// lab.yaml and hands resolved, already-validated values to the shell
// scripts that do the provisioning. It never touches the network or
// libvirt itself.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
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
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: labctl validate <lab.yaml>")
	fmt.Fprintln(os.Stderr, "       labctl resolve <lab.yaml> <cell-name>")
	os.Exit(2)
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
