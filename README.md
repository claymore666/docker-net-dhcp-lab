# docker-net-dhcp-lab

Runs [docker-net-dhcp](https://github.com/claymore666/docker-net-dhcp) against
real DHCP servers and routers, each installed the way its users install it,
and publishes what passed.

Work in progress. The repository becomes public once the first results page
exists.

## Bring up the reference cell

```
scripts/bootstrap-host.sh          # once per lab host
scripts/demo-ref-cell.sh ref-only  # one command, issue #1
scripts/down-cell.sh ref-only <work-dir>  # tear it back down
```

`lab.yaml` declares the cells; `verify.sh` is the arbiter (CI runs it on
every push and PR).

Every VM boots UEFI (OVMF); its per-VM NVRAM copy lives under the cell's
work directory and `down-cell.sh` removes it. `up-cell.sh` refuses to
attach a VM to `net-mgmt` unless the host's `ci_dmz` firewall chain is
present at priority -10 with a rule that drops by destination
(`scripts/containment-preflight.sh`, run via `sudo -n` since reading
nftables state needs root). That check only reads the ruleset text; it
cannot prove traffic is actually blocked end to end. The proof of that
is `dmz-probe.sh ""` run inside the Docker host VM at a live run, not
this preflight.

## Bring up a source cell

Kea, ISC dhcpd and dnsmasq each get their own cell, apt-installed with a
stock config plus a pool (issue #2). A Go adapter reads each source's
own lease table (control API, `dhcpd.leases`, or the dnsmasq lease
file) rather than trusting the plugin's own report.

```
scripts/demo-source-cell.sh kea        # or isc-dhcp, or dnsmasq
scripts/down-cell.sh kea <work-dir>
```

`labctl leases <source-type> <mgmt-ip> <known-hosts>` prints one
source's table on its own, through the same adapter.

## Run the group-A scenarios

`scripts/run-group-a.sh <cell-name> [work-dir] [evidence-dir]` brings a
cell up, runs the group-A scenarios (first lease, container restart,
compose down/up, daemon restart, host reboot, host reboot with a fixed
`mac_address`, plugin upgrade, plugin killed, fleet burst) across all
three null-IPAM network shapes, and tears the cell back down. One
evidence bundle is left behind: the resolved `lab.yaml`,
plugin/engine/kernel versions, a config diff from the source's stock
install, one packet capture spanning the whole run, lease-table
snapshots, the plugin's own log, and one verdict file per scenario x
shape.

A scenario a source cannot run (for example, a capability it does not
declare) is recorded N/A with a reason, never skipped silently. A FAIL
is a finding about the plugin, not the runner; the runner never retries
or tunes a scenario to make it pass.

On `ipvlan`, the container-restart and host-reboot verdicts pass with a
note instead of failing when the address changes: the plugin writes no
tombstone for `ipvlan` and its client id does not survive a restart, so
a new address there is documented behaviour, not a plugin defect (see
`docs/reference.md` "Restart stability (MAC and IP)", #219, in the
plugin repo). The verdict still requires a lease under the new address
and that the source can reach the container.

Under the hood, `labctl run <lab.yaml> <repo-root> <cell-name>
<bridge|macvlan|ipvlan> <work-dir> <evidence-dir> <pcap-path|->` runs
one shape's scenarios directly, for a single-shape re-run.

### Verdict file format

One file per scenario x cell x shape, named
`<cell>-<shape>-<scenario>.verdict`; a re-run overwrites its own prior
file rather than adding another one. Plain `key: value` lines:

```
scenario: A1-first-lease
cell: kea
shape: bridge
result: PASS
reason: lease confirmed in the source's own table
git_sha: <commit the run used>
timestamp: 2026-01-01T00:00:00Z
evidence.lease_after: <path>
```

`result` is `PASS`, `FAIL` or `N/A`. A `PASS` always carries at least
one `evidence.<label>: <path>` line pointing at a real, non-empty file
in the bundle; an `N/A` carries none, only a `reason`. This is the
interface issue #4's results matrix reads.

## Results page

`labctl matrix --root <bundle-root> [--out results/<tag>.md] [--asset
<name>] <bundle-dir> [<bundle-dir> ...]` reads one or more evidence
bundles and writes the results page: one row per scenario, in plain
words (never a scenario id), one column per cell x shape, each cell a
`PASS`/`FAIL`/`N/A`/`BLOCKED` link straight to its verdict file, written
relative to `--root` so the same page still resolves once `--root` is a
packed bundle's own extracted directory, and refused outright if
`--root` is not actually an ancestor of a bundle rather than writing a
link that leaves it. A verdict `labctl matrix` cannot find for a
scenario x column prints `(missing)` rather than being left out of the
table. `--asset` names the release asset the page's relative links live
in, printed once in the header; it is optional, and the header is
unchanged without it. The plain-word names live in one place,
`internal/matrix/names.go`.

## Coverage check

`labctl coverage (--tag vX.Y.Z | --file path/to/reference.md)` reads the
plugin repo's `docs/reference.md` at a tag (or a local file, for tests or
a pinned copy) and checks its three option tables (driver options,
per-endpoint options, plugin settings) against `internal/coverage/mapping.go`,
this lab's own reviewed record of which option a scenario actually
exercises. An option with neither a scenario nor a recorded reason
("not covered yet, planned", for example) fails the check and is named
in its output. It is a `labctl` subcommand, not a `verify.sh` step:
`verify.sh` is deliberately network-free (its own header comment), and
there is no pinned local copy of `docs/reference.md` in this repo to run
it against instead.

## Packing a bundle for release

`scripts/pack.sh <bundle-dir> <out.tar.gz> <denylist-file>` turns one
evidence bundle into a compressed tarball for a GitHub release asset
(attaching it to a release is a separate, later step, not this
script's). The denylist is required, as a third argument or via
`LAB_PACK_DENYLIST`: it is a local list of names that must not appear,
kept outside this repo, and packing refuses outright, with no tarball
written, if it is missing or its path names no real file, rather than
silently skipping that check. Packing also refuses, and writes nothing,
when the bundle carries a disallowed address (the same patterns
`scripts/hygiene-check.sh` uses, shared via
`scripts/hygiene-patterns.sh` rather than a second copy -- Docker's own
default bridge range and Kea's stock example config range are both
allowed, since neither is LAN detail), a hostname in a captured
`journalctl` line that is not this lab's own generated shape (`lab-*`),
or a `evidence.<label>` line in a verdict file naming a path outside the
bundle (an older run's own machine layout, never real evidence). A
packet capture (`.pcap`) is never text-scanned by this check; nothing in
this repo reads one automatically today, so each is checked by hand
before a bundle is packed.
