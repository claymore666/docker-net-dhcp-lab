// labctl is the lab's Go control plane: it owns lab.yaml and hands
// resolved, already-validated values to the shell scripts that do the
// provisioning. It never touches the network or libvirt itself.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/labyaml"
	"github.com/claymore666/docker-net-dhcp-lab/internal/scenario"
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// labErrorExitCode signals a lab-side abort, distinct from an ordinary
// tool failure (1) or a clean BLOCKED-for-unready-plugin run (0):
// run-group-a.sh's shape loop treats this one specially and aborts the
// whole cell rather than trying the remaining shapes against the same
// undersized pool (#3).
const labErrorExitCode = 3

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
	case "matrix":
		os.Exit(cmdMatrix(os.Args[2:]))
	case "coverage":
		os.Exit(cmdCoverage(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: labctl validate <lab.yaml>")
	fmt.Fprintln(os.Stderr, "       labctl resolve <lab.yaml> <cell-name>")
	fmt.Fprintln(os.Stderr, "       labctl leases <source-type> <mgmt-ip> <known-hosts>")
	fmt.Fprintln(os.Stderr, "       labctl run <lab.yaml> <repo-root> <cell-name> <bridge|macvlan|ipvlan|bridge-ipam|macvlan-ipam> <work-dir> <evidence-dir> <pcap-path|-> [scenario-name,...]")
	fmt.Fprintln(os.Stderr, "       labctl matrix --root <bundle-root> [--out <path>] <bundle-dir> [<bundle-dir> ...]")
	fmt.Fprintln(os.Stderr, "       labctl coverage (--tag vX.Y.Z | --file path/to/reference.md)")
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

// selectScenarios narrows catalog to the comma-separated Names in
// filterArg, in catalog's own order (never the filter's), so a debug
// pass over "A10-kill-restart-policy,A5b-host-reboot-fixed-mac" still
// runs A5b before A10 (#3). An empty filterArg returns catalog
// unchanged; an unknown name is silently dropped rather than failing
// the run, so a typo in a manual debug invocation runs fewer scenarios
// instead of none.
func selectScenarios(catalog []scenario.Scenario, filterArg string) []scenario.Scenario {
	if filterArg == "" {
		return catalog
	}
	want := map[string]bool{}
	for _, name := range strings.Split(filterArg, ",") {
		if name = strings.TrimSpace(name); name != "" {
			want[name] = true
		}
	}
	var out []scenario.Scenario
	for _, s := range catalog {
		if want[s.Name] {
			out = append(out, s)
		}
	}
	return out
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
	if len(args) != 7 && len(args) != 8 {
		usage()
	}
	labYAML, repoRoot, cellName, shapeArg, workDir, evidenceDir, pcapArg := args[0], args[1], args[2], args[3], args[4], args[5], args[6]
	// An optional 8th arg narrows scenario.Catalog to a comma-separated
	// set of Names, for a debug-logging evidence pass over the two
	// scenarios it names rather than the whole shape (#3). Empty or
	// absent runs every scenario, unchanged from before this arg
	// existed.
	scenarioFilter := ""
	if len(args) == 8 {
		scenarioFilter = args[7]
	}
	scenariosToRun := selectScenarios(scenario.Catalog, scenarioFilter)

	shape := scenario.Shape(shapeArg)
	validShape := false
	for _, s := range scenario.Shapes {
		if s == shape {
			validShape = true
		}
	}
	if !validShape {
		fmt.Fprintf(os.Stderr, "labctl run: unknown shape %q, want one of bridge, macvlan, ipvlan, bridge-ipam, macvlan-ipam\n", shapeArg)
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
	// here (issue #3). A fresh bring-up's plugin can report done, and
	// even have a live process, before its socket actually answers.
	if err := scenario.WaitPluginReady(ctx, hostRunner); err != nil {
		logPath := filepath.Join(evidenceDir, fmt.Sprintf("%s-%s-plugin-not-ready.log", cellName, shape))
		if logErr := scenario.CapturePluginLog(ctx, hostRunner, logPath); logErr != nil {
			fmt.Fprintf(os.Stderr, "labctl run: plugin log capture also failed: %v\n", logErr)
			logPath = "(plugin log capture also failed: " + logErr.Error() + ")"
		}
		reason := fmt.Sprintf("plugin never became ready before the first scenario could start: %v; plugin log: %s", err, logPath)
		for _, s := range scenariosToRun {
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

	// Reset before every shape: the plugin's own default is
	// release_lease=never (docs/reference.md), so nothing else ever
	// frees a lease between shapes, and five shapes of fresh
	// MACs/client-ids on one pool otherwise ran it out -- a lab fault,
	// not a plugin defect (#3). Logged in evidence so a run's own
	// record shows the reset happened.
	if err := source.ResetLeases(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: ResetLeases:", err)
		return 1
	}
	resetLog := filepath.Join(evidenceDir, fmt.Sprintf("%s-%s-lease-reset.txt", cellName, shape))
	resetNote := fmt.Sprintf("%s source's lease database reset before this shape: cell=%s shape=%s sha=%s at=%s\n",
		cell.Source.Type, cellName, shape, gitSHA, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(resetLog, []byte(resetNote), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: could not write lease-reset evidence:", err)
		return 1
	}

	// Pre-shape pool-capacity check: a pool that cannot even cover one
	// shape's worst-case address need aborts the cell as a lab error
	// here, before any scenario runs, rather than surfacing 30+
	// scenarios later as pool-exhaustion FAILs that read like plugin
	// defects (#3).
	capacity, err := poolCapacity(cell.Source.PoolStart, cell.Source.PoolEnd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: pool capacity:", err)
		return 1
	}
	heldLeases, err := source.Leases(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run: Leases after reset:", err)
		return 1
	}
	if ok, reason := poolHasCapacityFor(capacity, len(heldLeases), scenario.MinPoolAddresses); !ok {
		reason = "pool cannot cover this shape's run: " + reason
		for _, s := range scenariosToRun {
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
		fmt.Fprintf(os.Stderr, "labctl run: %s\n", reason)
		return labErrorExitCode
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
		SegGateway:        strings.SplitN(cell.Source.SegAddress, "/", 2)[0],
	}

	// The two IPAM shapes hold a stopped container's DHCP identity for a
	// minute and hand it to whichever container starts next on the same
	// network (docs/reference.md, "Restart stability (MAC and IP)" -> "In
	// IPAM mode"); sixteen scenarios run back to back on one shared
	// network would let one scenario's container claim a previous
	// scenario's identity, reading as a flaky plugin result when the lab's
	// own scenario ordering was the actual cause. Isolating each scenario
	// onto a fresh network is scoped to the two IPAM shapes only: the
	// null-IPAM shapes carry no such hold (issue #3 part 2, lab fault, not
	// a plugin defect).
	isolateBetweenScenarios := shape == scenario.ShapeBridgeIPAM || shape == scenario.ShapeMacvlanIPAM
	var isolationLog *os.File
	if isolateBetweenScenarios {
		f, err := os.OpenFile(filepath.Join(evidenceDir, "isolation.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "labctl run: could not open isolation.log:", err)
			return 1
		}
		isolationLog = f
		defer isolationLog.Close()
	}

	failed := 0
	isolationMethod := ""
	for i, s := range scenariosToRun {
		if isolateBetweenScenarios && i > 0 {
			newNet, method, err := scenario.IsolateIPAMNetwork(ctx, hostRunner, cellName, shape, nil)
			if err != nil {
				// A failed isolation is a lab error, never a scenario
				// result: returning here writes no verdict at all for
				// this or any scenario still queued behind it, rather
				// than letting the next one run against (and fail
				// against) a network that IsolateIPAMNetwork itself
				// found gone (issue #3).
				fmt.Fprintln(os.Stderr, "labctl run: IsolateIPAMNetwork:", err)
				return 1
			}
			env.Network = newNet
			isolationMethod = method
			line := fmt.Sprintf("%s %s: before %s: %s\n", cellName, shape, s.Name, method)
			fmt.Print(line)
			if _, err := isolationLog.WriteString(line); err != nil {
				fmt.Fprintln(os.Stderr, "labctl run: could not write isolation.log:", err)
				return 1
			}
		}
		v := scenario.RunOne(ctx, s, env)
		// Recorded in the verdict itself, not only in isolation.log, so
		// a read of one verdict file says how its network was isolated
		// without needing the sibling log (issue #3).
		v.IsolationMethod = isolationMethod
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
			failed, len(scenariosToRun), cellName, shape)
	}
	return 0
}

// poolCapacity returns the number of addresses in an IPv4 pool,
// inclusive of both ends (issue #3 part 2). start and end are already
// validated as parseable, start-before-end IPv4 addresses by
// labyaml.Load, so an error here means this cell's own config
// validation has a gap, not something a lab run's environment caused.
func poolCapacity(start, end string) (int, error) {
	s, err := netip.ParseAddr(start)
	if err != nil {
		return 0, fmt.Errorf("pool_start %q: %w", start, err)
	}
	e, err := netip.ParseAddr(end)
	if err != nil {
		return 0, fmt.Errorf("pool_end %q: %w", end, err)
	}
	if !s.Is4() || !e.Is4() {
		return 0, fmt.Errorf("pool_start %q and pool_end %q must both be IPv4", start, end)
	}
	sb, eb := s.As4(), e.As4()
	sN, eN := binary.BigEndian.Uint32(sb[:]), binary.BigEndian.Uint32(eb[:])
	if eN < sN {
		return 0, fmt.Errorf("pool_end %q is before pool_start %q", end, start)
	}
	return int(eN-sN) + 1, nil
}

// poolHasCapacityFor reports whether a pool has at least need addresses
// free once held is subtracted from capacity, and a reason worth
// logging either way: the cell's pre-shape check calls this once,
// right after the lease database reset and before any scenario can
// mint a single new lease (#3).
func poolHasCapacityFor(capacity, held, need int) (bool, string) {
	free := capacity - held
	if free < need {
		return false, fmt.Sprintf("%d free address(es) (%d held of %d total), needs at least %d", free, held, capacity, need)
	}
	return true, fmt.Sprintf("%d free address(es) (%d held of %d total), at least %d needed", free, held, capacity, need)
}

func gitRevParseHEAD(repoRoot string) (string, error) {
	out, err := exec.Command("git", "-C", repoRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
