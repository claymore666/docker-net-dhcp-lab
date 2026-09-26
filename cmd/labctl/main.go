// labctl is the lab's Go control plane: it owns lab.yaml and hands
// resolved, already-validated values to the shell scripts that do the
// provisioning. It never touches the network or libvirt itself.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
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
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: labctl validate <lab.yaml>")
	fmt.Fprintln(os.Stderr, "       labctl resolve <lab.yaml> <cell-name>")
	fmt.Fprintln(os.Stderr, "       labctl leases <source-type> <mgmt-ip> <known-hosts>")
	fmt.Fprintln(os.Stderr, "       labctl run <lab.yaml> <repo-root> <cell-name> <bridge|macvlan|ipvlan> <work-dir> <evidence-dir> <pcap-path|-> ")
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
	a, err := newSourceAdapter(sourceType, runner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl leases:", err)
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

// newSourceAdapter is the one place that maps a lab.yaml source.type to
// its adapter; cmdLeases and cmdRun both call it so the mapping cannot
// drift between the two.
func newSourceAdapter(sourceType string, runner sourceadapter.Runner) (sourceadapter.Adapter, error) {
	switch sourceType {
	case "kea":
		return &sourceadapter.KeaAdapter{Runner: runner}, nil
	case "isc-dhcp":
		return &sourceadapter.ISCDHCPAdapter{Runner: runner}, nil
	case "dnsmasq":
		return &sourceadapter.DnsmasqAdapter{Runner: runner}, nil
	default:
		return nil, fmt.Errorf("unknown source type %q", sourceType)
	}
}

// cmdRun is issue #3's scenario runner: one cell x one shape, every
// scenario in scenario.Catalog, one verdict file per scenario written to
// evidenceDir. It never touches the network or libvirt directly except
// through scenario.NetworkUp/NetworkDown (docker-network-level actions
// over the docker host's own SSH runner, the same exception cmdLeases's
// SSH use already establishes for source reads) -- the actual VM/bridge
// provisioning stays in up-cell.sh, run before this by the caller.
//
// It returns an exit code rather than calling os.Exit itself: os.Exit
// skips every deferred call in the program, which would leave
// NetworkUp's network (and, for bridge mode, its host bridge) attached
// on any error path after it succeeds -- main() calls os.Exit once,
// after this function has returned and its defer has run.
func cmdRun(args []string) int {
	if len(args) != 7 {
		usage()
	}
	labYAML, repoRoot, cellName, shapeArg, workDir, evidenceDir, pcapArg := args[0], args[1], args[2], args[3], args[4], args[5], args[6]

	shape := scenario.Shape(shapeArg)
	validShape := false
	for _, s := range scenario.Shapes {
		if s == shape {
			validShape = true
		}
	}
	if !validShape {
		fmt.Fprintf(os.Stderr, "labctl run: unknown shape %q, want one of bridge, macvlan, ipvlan\n", shapeArg)
		return 2
	}

	cfg, err := labyaml.Load(labYAML)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}
	cell, err := cfg.CellByName(cellName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}
	if cell.Source == nil {
		fmt.Fprintf(os.Stderr, "labctl run: cell %s has no source; nothing group A can run against\n", cellName)
		return 1
	}

	if err := os.MkdirAll(workDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}

	knownHosts := filepath.Join(workDir, "known_hosts")
	keyPath := os.ExpandEnv("$HOME/.ssh/id_ed25519_lab")
	hostMgmtIP := strings.SplitN(cell.DockerHost.MgmtAddress, "/", 2)[0]
	sourceMgmtIP := strings.SplitN(cell.Source.MgmtAddress, "/", 2)[0]

	hostRunner := sourceadapter.SSHRunner{Host: hostMgmtIP, User: "lab", KeyPath: keyPath, KnownHosts: knownHosts}
	sourceRunner := sourceadapter.SSHRunner{Host: sourceMgmtIP, User: "lab", KeyPath: keyPath, KnownHosts: knownHosts}
	source, err := newSourceAdapter(cell.Source.Type, sourceRunner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}

	gitSHA, err := gitRevParseHEAD(repoRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: git rev-parse HEAD:", err)
		return 1
	}

	pcap := pcapArg
	if pcap == "-" {
		pcap = ""
	}

	ctx := context.Background()

	// The readiness gate every scenario relies on (RunOne's
	// ensurePluginKnownState) only runs starting with the first
	// scenario; NetworkUp runs before that, so it needs its own gate
	// here (issue #3, lead directive 2026-09-26). A fresh bring-up's
	// plugin can report done, and even have a live process, before its
	// socket actually answers.
	if err := scenario.WaitPluginReady(ctx, hostRunner); err != nil {
		logPath := filepath.Join(evidenceDir, fmt.Sprintf("%s-%s-plugin-not-ready.log", cellName, shape))
		if logErr := scenario.CapturePluginLog(ctx, hostRunner, logPath); logErr != nil {
			fmt.Fprintf(os.Stderr, "labctl run: plugin log capture also failed: %v\n", logErr)
			logPath = "(plugin log capture also failed: " + logErr.Error() + ")"
		}
		reason := fmt.Sprintf("plugin never became ready before the first scenario could start: %v; plugin log: %s", err, logPath)
		for _, s := range scenario.Catalog {
			v := scenario.Verdict{
				Scenario: s.Name, Cell: cellName, Shape: shape,
				Result: scenario.BLOCKED, Reason: reason,
				GitSHA: gitSHA, Timestamp: time.Now(),
			}
			if werr := scenario.Write(evidenceDir, v); werr != nil {
				fmt.Fprintf(os.Stderr, "labctl run: %s/%s/%s: could not write verdict: %v\n", cellName, shape, s.Name, werr)
				return 1
			}
			fmt.Printf("%s %s %s: %s (%s)\n", cellName, shape, s.Name, v.Result, v.Reason)
		}
		return 0
	}

	net, err := scenario.NetworkUp(ctx, hostRunner, cellName, shape)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: NetworkUp:", err)
		return 1
	}
	defer scenario.NetworkDown(ctx, hostRunner, cellName, shape)

	env := scenario.Env{
		Host:              hostRunner,
		Source:            source,
		Cell:              cellName,
		Shape:             shape,
		Network:           net,
		PCAP:              pcap,
		RepoRoot:          repoRoot,
		WorkDir:           workDir,
		EvidenceDir:       evidenceDir,
		PluginTag:         cell.DockerHost.PluginTag,
		PreviousPluginTag: cell.DockerHost.PreviousPluginTag,
		GitSHA:            gitSHA,
	}

	failed := 0
	for _, s := range scenario.Catalog {
		v := scenario.RunOne(ctx, s, env)
		if err := scenario.Write(evidenceDir, v); err != nil {
			fmt.Fprintf(os.Stderr, "labctl run: %s/%s/%s: could not write verdict: %v\n", cellName, shape, s.Name, err)
			return 1
		}
		fmt.Printf("%s %s %s: %s (%s)\n", cellName, shape, s.Name, v.Result, v.Reason)
		if v.Result == scenario.FAIL {
			failed++
		}
	}
	if failed > 0 {
		fmt.Printf("labctl run: %d/%d scenarios FAILed on %s/%s; see verdicts\n",
			failed, len(scenario.Catalog), cellName, shape)
	}
	return 0
}

func gitRevParseHEAD(repoRoot string) (string, error) {
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
