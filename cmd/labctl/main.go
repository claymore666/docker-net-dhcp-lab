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
// run-cell.sh's shape loop treats this one specially and aborts the
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
	case "remaining":
		os.Exit(cmdRemaining(os.Args[2:]))
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
	fmt.Fprintln(os.Stderr, "       labctl remaining <lab.yaml> <cell-name> <bridge|macvlan|ipvlan|bridge-ipam|macvlan-ipam> <evidence-dir>")
	fmt.Fprintln(os.Stderr, "       labctl matrix --root <bundle-root> [--out <path>] <bundle-dir> [<bundle-dir> ...]")
	fmt.Fprintln(os.Stderr, "       labctl coverage (--tag vX.Y.Z | --file path/to/reference.md | --pinned vX.Y.Z) [--regen]")
	fmt.Fprintln(os.Stderr, "       labctl coverage pin --plugin-tree <dir> --tag vX.Y.Z")
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
	// Resolved alongside the cell, never duplicated into lab.yaml itself
	// (#8): up-cell.sh/up-source.sh get the base image's distro/suite/
	// os-variant this way, from the one Go registry, instead of a second
	// hand-kept copy of the mapping in shell.
	dockerHostImage, err := labyaml.LookupBaseImage(cell.DockerHost.BaseImage)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve:", err)
		os.Exit(1)
	}
	var sourceImage *labyaml.BaseImage
	if cell.Source != nil {
		si, err := labyaml.LookupBaseImage(cell.Source.BaseImage)
		if err != nil {
			fmt.Fprintln(os.Stderr, "labctl resolve:", err)
			os.Exit(1)
		}
		sourceImage = &si
	}
	relayImage, relayCfg, err := resolveRelay(cell)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve:", err)
		os.Exit(1)
	}
	out := struct {
		Management      labyaml.Management `json:"management"`
		ULAPrefix       string             `json:"ula_prefix"`
		Cell            *labyaml.Cell      `json:"cell"`
		DockerHostImage labyaml.BaseImage  `json:"docker_host_image"`
		SourceImage     *labyaml.BaseImage `json:"source_image"`
		RelayImage      *labyaml.BaseImage `json:"relay_image"`
		RelayFiles      *relayFiles        `json:"relay_files"`
		SourceServesV6  bool               `json:"source_serves_v6"`
	}{cfg.Management, cfg.ULAPrefix, cell, dockerHostImage, sourceImage, relayImage, relayCfg,
		cell.Source != nil && labyaml.SourceServesV6(cell.Source.Type)}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "labctl resolve: encode:", err)
		os.Exit(1)
	}
}

// relayFiles are the relay VM's two config files, rendered by the same
// Go code its Ready check compares against (#11), so up-relay.sh never
// keeps a second copy.
type relayFiles struct {
	Defaults string `json:"defaults"`
	Nft      string `json:"nft"`
}

func resolveRelay(cell *labyaml.Cell) (*labyaml.BaseImage, *relayFiles, error) {
	if cell.Relay == nil {
		return nil, nil, nil
	}
	img, err := labyaml.LookupBaseImage(cell.Relay.BaseImage)
	if err != nil {
		return nil, nil, err
	}
	defaults, err := sourceadapter.RenderRelayDefaults(relayParams(cell))
	if err != nil {
		return nil, nil, err
	}
	return &img, &relayFiles{Defaults: defaults, Nft: sourceadapter.RelayNftRuleset}, nil
}

// relayParams maps a relay cell's lab.yaml addresses onto WithRelay (#11).
func relayParams(cell *labyaml.Cell) sourceadapter.RelayParams {
	return sourceadapter.RelayParams{
		ClientAddr:   cell.Relay.ClientAddress,
		ServerAddr:   cell.Relay.ServerAddress,
		SourceAddr:   hostPart(cell.Source.SegAddress),
		ClientSubnet: cell.Segment.Subnet,
		PoolStart:    cell.Source.PoolStart,
		AgentOptions: cell.Relay.AgentOptions,
	}
}

func hostPart(cidr string) string { return strings.SplitN(cidr, "/", 2)[0] }

// cellEnv builds the cell half of a run's Env: the source adapter, wrapped
// with the relay's Ready checks and Recover in a relay cell, and the router,
// source, relay and second-capture fields (#11). dial opens a runner on a
// management address; cmdRun fills the shape half.
func cellEnv(ctx context.Context, cell *labyaml.Cell, cellName, repoRoot, workDir string, dial func(host string) sourceadapter.Runner) (scenario.Env, error) {
	// One runner per host, so the adapter and the relay's source probes
	// share the primary's retry state.
	sourceHost := hostPart(cell.Source.MgmtAddress)
	sourceRunner := dial(sourceHost)
	source, err := newCellSourceAdapter(cell.Source, func(mgmt string) sourceadapter.Runner {
		if hostPart(mgmt) == sourceHost {
			return sourceRunner
		}
		return dial(hostPart(mgmt))
	})
	if err != nil {
		return scenario.Env{}, err
	}
	env := scenario.Env{
		Cell:      cellName,
		RepoRoot:  repoRoot,
		WorkDir:   workDir,
		SegSubnet: cell.Segment.Subnet,
		PoolStart: cell.Source.PoolStart,
		PoolEnd:   cell.Source.PoolEnd,
		Capture:   scenario.ObserverCapture{Cell: cellName, RepoRoot: repoRoot},
	}
	env.SegGateway, env.SourceAddr = segAddresses(cell)
	if cell.Relay != nil {
		relayRunner := dial(hostPart(cell.Relay.MgmtAddress))
		p := relayParams(cell)
		p.Source = sourceRunner
		source = sourceadapter.WithRelay(source, relayRunner, p)
		if env.RelayClientMAC, env.RelayServerMAC, err = sourceadapter.RelayMACs(ctx, relayRunner); err != nil {
			return scenario.Env{}, err
		}
		env.ServerPCAP = filepath.Join(workDir, "srv", "observer.pcap")
		env.ServerCapture = scenario.ObserverCapture{Cell: cellName + "-srv", RepoRoot: repoRoot}
	}
	env.Source = source
	return env, nil
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
	case "udhcpd":
		return &sourceadapter.UdhcpdAdapter{Runner: runner}, nil
	case "pihole":
		return &sourceadapter.PiholeAdapter{Runner: runner}, nil
	case "routeros":
		return &sourceadapter.RouterOSAdapter{Runner: runner}, nil
	case "openwrt":
		return &sourceadapter.OpenwrtAdapter{Runner: runner}, nil
	default:
		return nil, fmt.Errorf("unknown source type %q", sourceType)
	}
}

// newCellSourceAdapter returns the cell's source adapter: the single
// adapter, or a PairAdapter over both peers when source.partner is set
// (lab #12), each peer reached by its own runner.
func newCellSourceAdapter(src *labyaml.Source, runnerFor func(mgmtAddress string) sourceadapter.Runner) (sourceadapter.Adapter, error) {
	if src.Partner == nil {
		return newSourceAdapter(src.Type, runnerFor(src.MgmtAddress))
	}
	ip := func(cidr string) string { return strings.SplitN(cidr, "/", 2)[0] }
	switch src.Type {
	case "kea":
		return sourceadapter.NewKeaPair(runnerFor(src.MgmtAddress), runnerFor(src.Partner.MgmtAddress),
			ip(src.SegAddress), ip(src.Partner.SegAddress)), nil
	case "isc-dhcp":
		return sourceadapter.NewISCPair(runnerFor(src.MgmtAddress), runnerFor(src.Partner.MgmtAddress),
			ip(src.SegAddress), ip(src.Partner.SegAddress)), nil
	default:
		return nil, fmt.Errorf("source type %q cannot run as a failover pair", src.Type)
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

// remainingScenarioNames returns catalog's own names, in catalog order,
// leaving out any name in done (#8's resume support: a re-run passes
// this straight back into labctl run's existing scenario-filter arg, so
// a scenario that already has a verdict in the bundle is never re-run).
func remainingScenarioNames(catalog []scenario.Scenario, done map[string]bool) []string {
	var out []string
	for _, s := range catalog {
		if !done[s.Name] {
			out = append(out, s.Name)
		}
	}
	return out
}

// cmdRemaining prints the comma-separated scenario names cell/shape has
// not yet got a verdict for in evidenceDir, reading each *.verdict
// file's own content (never its file name, matching ReadVerdict's own
// rule) so a resumed run-cell.sh can pass the result straight into
// `labctl run`'s existing scenario-filter argument. Prints an empty line
// when every catalog scenario already has one.
func cmdRemaining(args []string) int {
	if len(args) != 4 {
		usage()
	}
	labYAML, cellName, shapeArg, evidenceDir := args[0], args[1], args[2], args[3]
	cfg, err := labyaml.Load(labYAML)
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl remaining:", err)
		return 1
	}
	if _, err := cfg.CellByName(cellName); err != nil {
		fmt.Fprintln(os.Stderr, "labctl remaining:", err)
		return 1
	}
	matches, err := filepath.Glob(filepath.Join(evidenceDir, "*.verdict"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl remaining:", err)
		return 1
	}
	done := map[string]bool{}
	for _, m := range matches {
		v, err := scenario.ReadVerdict(m)
		if err != nil {
			fmt.Fprintln(os.Stderr, "labctl remaining:", err)
			return 1
		}
		if v.Cell == cellName && string(v.Shape) == shapeArg {
			done[v.Scenario] = true
		}
	}
	fmt.Println(strings.Join(remainingScenarioNames(scenario.Catalog, done), ","))
	return 0
}

// hostInfo reads the docker host's own distro, kernel and engine version
// over host (issue #8), best-effort: a read that fails leaves the zero
// HostInfo rather than aborting the run, since a host detail is
// something a verdict carries, not something it depends on.
func hostInfo(ctx context.Context, host sourceadapter.Runner) scenario.HostInfo {
	var hi scenario.HostInfo
	if out, err := host.Run(ctx, ". /etc/os-release && echo \"$PRETTY_NAME\""); err == nil {
		hi.Distro = strings.TrimSpace(out)
	}
	if out, err := host.Run(ctx, "uname -r"); err == nil {
		hi.Kernel = strings.TrimSpace(out)
	}
	if out, err := host.Run(ctx, "sudo docker version --format '{{.Server.Version}}'"); err == nil {
		hi.DockerVersion = strings.TrimSpace(out)
	}
	return hi
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
		fmt.Fprintf(os.Stderr, "labctl run: cell %s has no source; no scenario can run against it\n", cellName)
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
	// 5 min covers the longest new-connection outage the #38 -j 6 run measured (about 4 min).
	hostRunner := &sourceadapter.RetryRunner{Bound: 5 * time.Minute, Poll: 2 * time.Second, Log: os.Stderr,
		Inner: sourceadapter.SSHRunner{Host: hostMgmtIP, User: "lab", KeyPath: keyPath, KnownHosts: knownHosts}}
	env, err := cellEnv(context.Background(), cell, cellName, repoRoot, workDir, func(host string) sourceadapter.Runner {
		return &sourceadapter.RetryRunner{Bound: 5 * time.Minute, Poll: 2 * time.Second, Log: os.Stderr,
			Inner: sourceadapter.SSHRunner{Host: host, User: "lab", KeyPath: keyPath, KnownHosts: knownHosts}}
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", err)
		return 1
	}
	source := env.Source

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
	hi := hostInfo(ctx, hostRunner)

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
				GitSHA: gitSHA, Timestamp: time.Now(), Host: hi,
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
	if ok, reason := poolHasCapacityFor(capacity, len(heldLeases), scenario.PoolDemand(scenariosToRun, source)); !ok {
		reason = "pool cannot cover this shape's run: " + reason
		for _, s := range scenariosToRun {
			v := scenario.Verdict{
				Scenario: s.Name, Cell: cellName, Shape: shape,
				Result: scenario.BLOCKED, Reason: reason,
				GitSHA: gitSHA, Timestamp: time.Now(), Host: hi,
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

	// The previous shape's macvlan/ipvlan network can still hold the
	// parent NIC when this process starts, and the plugin then refuses
	// every container with "would not accept another child" (23 kea
	// FAILs in the first six-cell run, lab#38). Wait, bounded, for a
	// clean parent and keep the wait in the evidence bundle; a parent
	// that never clears is plugin evidence, so the shape is BLOCKED and
	// names the leftover link. No scenario is ever retried. A bridge shape
	// cannot take a NIC with a child as its port, so this runs before every shape.
	blockedReason, perr := scenario.ParentReady(ctx, hostRunner, cellName, shape, evidenceDir, scenario.ParentCleanWindow, scenario.ParentCleanPoll)
	if perr != nil {
		fmt.Fprintln(os.Stderr, "labctl run:", perr)
		return 1
	}
	if blockedReason != "" {
		for _, s := range scenariosToRun {
			v := scenario.Verdict{
				Scenario: s.Name, Cell: cellName, Shape: shape,
				Result: scenario.BLOCKED, Reason: blockedReason,
				GitSHA: gitSHA, Timestamp: time.Now(), Host: hi,
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

	env.Host = hostRunner
	env.Shape = shape
	env.Network = net
	env.PCAP = pcap
	env.EvidenceDir = evidenceDir
	env.PluginTag = cell.DockerHost.PluginTag
	env.PreviousPluginTag = cell.DockerHost.PreviousPluginTag
	env.GitSHA = gitSHA
	env.HostInfo = hi

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

// segAddresses is the router and the source address a cell's Env carries;
// without a relay both are seg_address stripped of its CIDR suffix, behind
// a relay the router is the relay's client leg (#11).
func segAddresses(cell *labyaml.Cell) (segGateway, sourceAddr string) {
	sourceAddr = hostPart(cell.Source.SegAddress)
	if cell.Relay != nil {
		return hostPart(cell.Relay.ClientAddress), sourceAddr
	}
	return sourceAddr, sourceAddr
}
