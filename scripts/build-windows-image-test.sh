#!/bin/bash
# The Windows image recipe (lab #14), with no Windows, ISO, VM or network:
# the rendered answer file and first-logon script, the build id, every
# refusal before a VM exists, the build driven against stubbed virt-install,
# virsh and ssh (clock, devices, bound, second boot, no password anywhere
# a log could keep it), the recording, and up-source.sh's render path.
set -euo pipefail
export LC_ALL=C
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

tmp=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$tmp"' EXIT
fail=0
bad() {
	echo "build-windows-image-test: $*" >&2
	fail=1
}
export LAB_PUBKEY="ssh-ed25519 AAAA render-only"
B=./scripts/build-windows-image.sh

# The windows cell is the one lab.yaml declares (lab #14); a copy lets the
# test edit it without touching the file.
cp lab.yaml "$tmp/lab.yaml"
export LAB_YAML="$tmp/lab.yaml"
go run ./cmd/labctl validate "$LAB_YAML" >/dev/null || bad "lab.yaml does not validate"

# --- stubs -----------------------------------------------------------------
stub=$tmp/stub
mkdir -p "$stub" "$tmp/cap"
cat >"$stub/sudo" <<'STUB'
#!/bin/bash
[ "$1" = -n ] && shift
echo "sudo $*" >>"$STUB_LOG"
if [ "$1" = cp ] && [ ! -f "$3" ]; then : >"${@: -1}"; exit 0; fi
exec "$@"
STUB
cat >"$stub/virt-install" <<'STUB'
#!/bin/bash
echo "virt-install $*" >>"$STUB_LOG"
STUB
cat >"$stub/virsh" <<'STUB'
#!/bin/bash
echo "virsh $*" >>"$STUB_LOG"
case "$1" in
dominfo) [ -n "${STUB_DOMINFO_EXISTS:-}" ] && [ "$2" = lab-windows-source ] ;;
domstate) if [ -n "${STUB_RUNNING_FOREVER:-}" ]; then echo running; else echo "shut off"; fi ;;
*) exit 0 ;;
esac
STUB
cat >"$stub/qemu-img" <<'STUB'
#!/bin/bash
echo "qemu-img $*" >>"$STUB_LOG"
[ "$1" = create ] && : >"$4"
exit 0
STUB
cat >"$stub/genisoimage" <<'STUB'
#!/bin/bash
echo "genisoimage $*" >>"$STUB_LOG"
out=; files=()
while [ $# -gt 0 ]; do
	case "$1" in
	-output) out=$2; shift 2 ;;
	-volid) echo "volid $2" >>"$STUB_LOG"; shift 2 ;;
	-*) shift ;;
	*) files+=("$1"); shift ;;
	esac
done
: >"$out"
n=$(ls "$STUB_CAP" | wc -l)
mkdir -p "$STUB_CAP/$n"
cp "${files[@]}" "$STUB_CAP/$n/"
STUB
cat >"$stub/osinfo-query" <<'STUB'
#!/bin/bash
[ -z "${STUB_NO_WIN2K25:-}" ]
STUB
cat >"$stub/ssh" <<'STUB'
#!/bin/bash
enc=${*: -1}
text=$(printf '%s' "$enc" | base64 -d | iconv -f UTF-16LE -t UTF-8)
echo "ssh-call $* :: $text" >>"$STUB_LOG"
printf '%s\n' "$text" >>"$STUB_SSH_TEXT"
if [ -n "${STUB_FAIL_ON:-}" ] && grep -qF -- "$STUB_FAIL_ON" <<<"$text"; then exit 1; fi
case "$text" in
*bootstrap-done*Get-Service*) if [ -n "${STUB_SSH_BAD:-}" ]; then echo "other Running"; else echo "$STUB_ID Running"; fi ;;
*) echo stub-output ;;
esac
STUB
chmod +x "$stub"/*
export STUB_LOG=$tmp/calls.log STUB_CAP=$tmp/cap STUB_SSH_TEXT=$tmp/ssh.txt
export WINDOWS_BUILD_TICK=0.05 WINDOWS_BUILD_KEY_SLEEP=0
: >"$STUB_LOG"
: >"$STUB_SSH_TEXT"

# --- render ----------------------------------------------------------------
id=$($B --render windows "$tmp/r")
ua=$tmp/r/autounattend.xml
fl=$tmp/r/firstlogon.ps1
[ "$($B --id windows)" = "$id" ] || bad "--id and --render disagree"
[[ "$id" =~ ^[0-9a-f]{64}$ ]] || bad "the id is not a sha256: $id"
cat "$ua" "$fl" | grep -nE '__[A-Z0-9_]+__' >/dev/null && bad "an unfilled placeholder is left: $(grep -hoE '__[A-Z0-9_]+__' "$ua" "$fl" | sort -u | tr '\n' ' ')"
# python3's parser, not xmllint: the hosted runner has no libxml2-utils (lab #14).
wellformed() { python3 -I -c 'import sys, xml.etree.ElementTree as E; E.parse(sys.argv[1])' "$1" 2>/dev/null; }
command -v python3 >/dev/null || bad "python3 is needed for the well-formedness check"
printf '<a><b></a>\n' >"$tmp/broken.xml"
if wellformed "$tmp/broken.xml"; then bad "the well-formedness check accepts a broken file"; fi
wellformed "$ua" || bad "autounattend.xml is not well-formed"
grep -qF "<Value>Windows Server 2025 SERVERSTANDARDCORE</Value>" "$ua" || bad "the image is not selected by name"
grep -qE '^WIN_IMAGE_NAME=.Windows Server 2025 SERVERSTANDARDCORE.$' scripts/build-windows-image.sh || bad "the image name constant moved from the answer file's"
grep -qF "$(grep -F 'Windows Server 2025 SERVERSTANDARDCORE' images/windows-2025-eval.sha256)" images/windows-2025-eval.sha256 || bad "the pin header does not name the image"
[ "$(grep -c '<Path>' "$ua")" -eq 16 ] || bad "driver paths: $(grep -c '<Path>' "$ua"), want 16"
for l in D E F G; do
	for d in viostor NetKVM; do
		grep -qF "<Path>$l:\\$d\\2k25\\amd64</Path>" "$ua" || bad "no driver path $l:\\$d\\2k25"
	done
done
grep -qF '<TimeZone>UTC</TimeZone>' "$ua" || bad "the time zone is not UTC"
grep -qF "'LABSEED'" "$ua" || bad "the first-logon command does not find the seed CD by label"

# The NICs are matched by MAC and the MACs are up-source.sh's scheme.
for f in scripts/up-source.sh scripts/build-windows-image.sh; do
	grep -F "md5sum | cut -c1-6" "$f" | sed 's/^[[:space:]]*//' >"$tmp/mac.$(basename "$f")"
done
cmp -s "$tmp/mac.up-source.sh" "$tmp/mac.build-windows-image.sh" || bad "mac_from differs between up-source.sh and the build script"
want_mgmt=$(echo -n lab-windows-source-mgmt | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52-54-00-\1-\2-\3/' | tr a-f A-F)
want_seg=$(echo -n lab-windows-source-seg | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52-54-00-\1-\2-\3/' | tr a-f A-F)
grep -qF "Mac = '$want_mgmt'" "$fl" || bad "no mgmt MAC $want_mgmt in the first-logon script"
grep -qF "Mac = '$want_seg'" "$fl" || bad "no segment MAC $want_seg in the first-logon script"
grep -qE "Name 'Ethernet|InterfaceAlias '?Ethernet|-Name Ethernet" "$fl" && bad "an adapter is addressed by its Windows name"
grep -qF "Ip = '10.200.16.2'; Prefix = 24" "$fl" || bad "no segment address in the first-logon script"
grep -qF "Ip = '10.200.255.161'; Prefix = 24; Gw = '10.200.255.1'" "$fl" || grep -qE "Ip = '10.200.255.161'; Prefix = 24; Gw = '[0-9.]+'" "$fl" || bad "no management address in the first-logon script"
grep -qF -- "-StartRange '10.200.16.100' -EndRange '10.200.16.200'" "$fl" || bad "no scope in the first-logon script"
grep -qF -- "-ConflictDetectionAttempts 0" "$fl" || bad "conflict detection is not the stock default"
grep -qF "'PasswordAuthentication no'" "$fl" || bad "sshd keeps password authentication"
grep -qF "'AutoAdminLogon' -Value '0'" "$fl" || bad "autologon is not switched off"
grep -qF "'DefaultPassword'" "$fl" || bad "the stored logon password is not removed"
grep -qE "^ +Remove-Item -Path 'C:.Windows.Panther.unattend.xml', 'C:.Windows.Panther.Unattend.unattend.xml', 'C:.Windows.System32.sysprep.unattend.xml' -Force" "$fl" || bad "Setup's cached answer files are not removed"
grep -qF "icacls.exe \$keys /inheritance:r /grant" "$fl" || bad "the authorized keys file keeps inherited permissions"
grep -qF 'S:\EFI\BOOT\bootx64.efi' "$fl" || bad "no UEFI fallback loader copy"
grep -qF "NoAutoUpdate" "$fl" || bad "automatic updates are not off"
grep -qF "InitialSize = [uint32]512; MaximumSize = [uint32]512" "$fl" || bad "the pagefile is not fixed at 512 MB"
for r in lab-icmp-in lab-dhcp-in lab-ssh-in; do grep -qF -- "-Name '$r'" "$fl" || bad "no firewall rule $r"; done
grep -qF "$LAB_PUBKEY" "$fl" || bad "the lab key is not baked"
# The marker is written once, last, and the next statement powers off.
[ "$(grep -c 'WriteAllText.*bootstrap-done' "$fl")" -eq 1 ] || bad "bootstrap-done is written more than once"
n=$(grep -n 'WriteAllText.*bootstrap-done' "$fl" | cut -d: -f1)
[ "$(sed -n "$((n + 1))p" "$fl")" = "    Stop-Computer -Force" ] || bad "the marker is not followed by Stop-Computer"
grep -qF "'$id'" "$fl" || bad "the rendered marker is not the printed id"

if command -v pwsh >/dev/null; then
	# shellcheck disable=SC2016 # the PowerShell program is a literal
	parse() {
		PSFILE=$1 pwsh -NoProfile -Command '$e = $null; $t = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:PSFILE, [ref]$t, [ref]$e); if ($e) { $e | ForEach-Object { $_.ToString() }; exit 1 }'
	}
	parse "$fl" || bad "firstlogon.ps1 does not parse"
	awk "/^        \\\$netconfig = @'\$/{on=1;next} /^'@\$/{on=0} on" "$fl" >"$tmp/netconfig.ps1"
	[ -s "$tmp/netconfig.ps1" ] || bad "the embedded netconfig script was not found"
	parse "$tmp/netconfig.ps1" || bad "netconfig.ps1 does not parse"
else
	echo "build-windows-image-test: SKIP the PowerShell parse (no pwsh here)"
fi

# --- id ----------------------------------------------------------------------
[ "$(umask 0077 && $B --id windows)" = "$id" ] || bad "--id moves with the umask"
sed '/^  - name: windows$/,$ s/pool_end: 10\.200\.16\.200/pool_end: 10.200.16.199/' "$tmp/lab.yaml" >"$tmp/lab2.yaml"
[ "$(LAB_YAML="$tmp/lab2.yaml" $B --id windows)" != "$id" ] || bad "a pool edit left the id unchanged"
[ "$(LAB_PUBKEY="ssh-ed25519 BBBB other" $B --id windows)" != "$id" ] || bad "a key change left the id unchanged"
printf '%s  windows-server-2025-eval.iso\n' "$(printf a | sha256sum | cut -d' ' -f1)" >"$tmp/pin-a"
[ "$(LAB_WINDOWS_ISO_PIN="$tmp/pin-a" $B --id windows)" != "$id" ] || bad "a pin change left the id unchanged"
if $B --id dnsmasq >"$tmp/o" 2>&1; then bad "a dnsmasq cell was accepted"; fi
grep -q REFUSED "$tmp/o" || bad "the dnsmasq refusal is not worded: $(cat "$tmp/o")"

# The image under another source type is refused, with the type named.
sed '/^  - name: windows$/,$ s/^      type: windows$/      type: dnsmasq/' "$tmp/lab.yaml" >"$tmp/lab3.yaml"
if cmp -s "$tmp/lab.yaml" "$tmp/lab3.yaml"; then bad "the source type edit did not apply"; fi
if LAB_YAML="$tmp/lab3.yaml" $B --id windows >"$tmp/o" 2>&1; then bad "a windows image under type dnsmasq was accepted"; fi
grep -q "has source type 'dnsmasq', not windows" "$tmp/o" || bad "the type refusal is not worded: $(cat "$tmp/o")"

# --- build refusals: a VM is never started -------------------------------------
export LAB_IMAGE_CACHE=$tmp/cache WINDOWS_BUILD_DIR=$tmp/cache/windows-build
mkdir -p "$LAB_IMAGE_CACHE/iso"
printf 'not a windows iso' >"$LAB_IMAGE_CACHE/iso/windows-server-2025-eval.iso"
printf 'not a virtio iso' >"$LAB_IMAGE_CACHE/iso/virtio-win.iso"
isosum=$(sha256sum "$LAB_IMAGE_CACHE/iso/windows-server-2025-eval.iso" | cut -d' ' -f1)
export PATH="$stub:$PATH"
export LAB_WINDOWS_ISO_PIN=$tmp/pin
refused() { # DESC WANT-SUBSTRING [env...]
	local desc=$1 want=$2
	shift 2
	: >"$STUB_LOG"
	if env "$@" $B windows >"$tmp/o" 2>"$tmp/e"; then
		bad "$desc: the build was accepted"
	elif ! grep -qF -- "$want" "$tmp/e"; then
		bad "$desc: refusal lacks '$want': $(cat "$tmp/e")"
	fi
	grep -q '^virt-install' "$STUB_LOG" && bad "$desc: a VM was started"
	return 0
}
cp images/windows-2025-eval.sha256 "$tmp/pin"
refused "the checked-in pin (header only)" "no checksum is pinned for the ISO in" "X=1"
printf '%s  x\n' "not-a-hash" >"$tmp/pin"
refused "a malformed pin" "is not a sha256" "X=1"
printf '%s  windows-server-2025-eval.iso\n' "$(printf b | sha256sum | cut -d' ' -f1)" >"$tmp/pin"
refused "a pin that differs from the ISO" "replace the pinned line in" "X=1"
printf '%s  windows-server-2025-eval.iso\n' "$isosum" >"$tmp/pin"
refused "an ISO that is not there" "is not there" "LAB_WINDOWS_ISO_DIR=$tmp/none"
mkdir -p "$tmp/noiso" && cp "$LAB_IMAGE_CACHE/iso/windows-server-2025-eval.iso" "$tmp/noiso/"
refused "no virtio ISO" "virtio-win.iso" "LAB_WINDOWS_ISO_DIR=$tmp/noiso"
refused "the cell's source domain exists" "tear the cell down first" "STUB_DOMINFO_EXISTS=1"
if $B dnsmasq >"$tmp/o" 2>"$tmp/e"; then bad "a dnsmasq cell was built"; fi
[ ! -e "$LAB_IMAGE_CACHE/windows-2025-eval.qcow2" ] || bad "a refused build left an image"

# The id covers the pin, so it is read with the pin the build will use.
printf '%s  windows-server-2025-eval.iso\n' "$isosum" >"$tmp/pin"
id=$($B --id windows)
export STUB_ID=$id

# --- a build against stubs -------------------------------------------------------
: >"$STUB_LOG"
: >"$STUB_SSH_TEXT"
$B windows >"$tmp/build.out" 2>&1 || bad "the stubbed build failed: $(tail -n 5 "$tmp/build.out")"
dest=$LAB_IMAGE_CACHE/windows-2025-eval
[ -f "$dest.qcow2" ] || bad "no golden image"
[ "$(cat "$dest.build-id" 2>/dev/null)" = "$id" ] || bad "the build-id sidecar is not the cell's id"
[ ! -e "$dest.qcow2.part" ] || bad "a .part file is left"
[ -z "$(ls -A "$WINDOWS_BUILD_DIR")" ] || bad "the work directory is left: $(ls "$WINDOWS_BUILD_DIR")"
vi=$(grep '^virt-install' "$STUB_LOG")
for want in "--clock offset=utc" "--memory 4096" "--vcpus 2" "--os-variant win2k25" "network=net-mgmt,model=virtio,mac=$(echo -n lab-windows-source-mgmt | md5sum | cut -c1-6 | sed -E 's/(..)(..)(..)/52:54:00:\1:\2:\3/')" "--import"; do
	grep -qF -- "$want" <<<"$vi" || bad "virt-install lacks '$want'"
done
[ "$(grep -o -- '--network' <<<"$vi" | wc -l)" -eq 1 ] || bad "the build VM has more than the management NIC"
[ "$(grep -o 'device=cdrom' <<<"$vi" | wc -l)" -eq 3 ] || bad "the build VM does not carry three CD-ROMs"
grep -qF "path=$LAB_IMAGE_CACHE/iso/windows-server-2025-eval.iso,device=cdrom,boot.order=1" <<<"$vi" || bad "the Windows ISO is not first in the boot order"
grep -q '^volid LABSEED$' "$STUB_LOG" || bad "the seed CD has no LABSEED label"
[ "$(grep -c '^virsh send-key' "$STUB_LOG")" -ge 1 ] || bad "no key was sent past the boot prompt"
grep -q '^virsh undefine lab-build-windows-2025-eval --nvram' "$STUB_LOG" || bad "the build domain was not removed"
# Order: install, off, fresh NVRAM, second boot, proof, power off.
order=$(grep -E '^virt-install|^sudo cp -f .*OVMF_VARS|^virsh start|^ssh-call .*Stop-Computer' "$STUB_LOG" |
	sed -E -e 's/^virt-install.*/install/' -e 's/^sudo cp.*/freshnvram/' -e 's/^virsh start.*/start/' -e 's/^ssh-call .*/poweroff/' | tr '\n' ' ')
[ "$order" = "install freshnvram start poweroff " ] || bad "the build steps are out of order: $order"
grep -qF "Get-Service -Name DHCPServer" "$STUB_SSH_TEXT" || bad "the second boot does not read the DHCP service"
# Passwords: drawn per build, found in the answer file only.
# The first password value is the administrator's, the one after the lab account's name is the lab's.
pwvals() { grep -A"$2" "$3" -e "$1" | grep -oE '<[A-Za-z]*Password><Value>[^<]+' | sed 's/.*<Value>//' | head -n1; }
pw1=$(grep -oE '<[A-Za-z]*Password><Value>[^<]+' "$STUB_CAP/0/autounattend.xml" | sed 's/.*<Value>//' | head -n1)
lab1=$(pwvals '<Name>lab</Name>' 3 "$STUB_CAP/0/autounattend.xml")
[ "${#pw1}" -ge 20 ] || bad "the administrator password is short or missing: ${#pw1}"
[ "$pw1" != "$lab1" ] || bad "the two accounts share a password"
for p in "$pw1" "$lab1"; do
	if grep -qF -- "$p" "$STUB_LOG" "$STUB_SSH_TEXT" "$tmp/build.out"; then bad "a password reached a command line, a remote command or the output"; fi
done
rm -f "$dest.qcow2" "$dest.build-id" "$dest.sources"
$B windows >/dev/null 2>&1 || bad "the second stubbed build failed"
pw2=$(grep -oE '<[A-Za-z]*Password><Value>[^<]+' "$STUB_CAP/1/autounattend.xml" | sed 's/.*<Value>//' | head -n1)
[ "$pw1" != "$pw2" ] || bad "two builds drew the same password"
grep -qF "$pw1" "$STUB_CAP/1/autounattend.xml" "$STUB_CAP/1/firstlogon.ps1" && bad "the second build carries the first password"
grep -q "$id" "$STUB_CAP/0/firstlogon.ps1" || bad "the built marker is not the cell's id"
rm -f "$dest.qcow2" "$dest.build-id" "$dest.sources"

# osinfo without win2k25 falls back to win2k22.
: >"$STUB_LOG"
STUB_NO_WIN2K25=1 $B windows >/dev/null 2>&1 || bad "the win2k22 fallback build failed"
grep -qF -- "--os-variant win2k22" "$STUB_LOG" || bad "no win2k22 fallback"
rm -f "$dest.qcow2" "$dest.build-id" "$dest.sources"

# The bound: a VM that never powers off is destroyed and nothing is kept.
: >"$STUB_LOG"
if STUB_RUNNING_FOREVER=1 WINDOWS_BUILD_TIMEOUT_S=1 $B windows >"$tmp/o" 2>"$tmp/e"; then bad "a VM that never powered off was accepted"; fi
grep -qF "did not power the VM off" "$tmp/e" || bad "the bound refusal is not worded: $(cat "$tmp/e")"
grep -q '^virsh destroy lab-build-windows-2025-eval' "$STUB_LOG" || bad "the build VM was not destroyed"
if [ -e "$dest.qcow2" ] || [ -e "$dest.build-id" ] || [ -e "$dest.qcow2.part" ]; then bad "a timed-out build left an image"; fi

# A second boot that does not read back this build's marker is refused.
: >"$STUB_LOG"
if STUB_SSH_BAD=1 $B windows >"$tmp/o" 2>"$tmp/e"; then bad "an image whose marker did not read back was accepted"; fi
grep -qF "did not read back" "$tmp/e" || bad "the proof refusal is not worded: $(cat "$tmp/e")"
if [ -e "$dest.qcow2" ] || [ -e "$dest.build-id" ]; then bad "an unproven build left an image"; fi
[ -z "$(ls -A "$WINDOWS_BUILD_DIR")" ] || bad "a refused build left its work directory"

# --- --record ----------------------------------------------------------------
: >"$STUB_SSH_TEXT"
$B --record windows "$tmp/rec" >/dev/null 2>&1 || bad "--record failed"
nrec=$(find "$tmp/rec" -type f | wc -l)
[ "$nrec" -eq 9 ] || bad "--record wrote $nrec files, want 9"
for f in "$tmp"/rec/*.txt; do
	head -n 1 "$f" | grep -qE "^# recorded [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z from lab-windows-source, image windows-2025-eval, build $id\$" || bad "$f has no dated header"
	[ "$(sed -n 2p "$f")" = stub-output ] || bad "$f does not carry the read's output"
done
grep -qF "ConvertTo-Json -InputObject @(Get-DhcpServerv4Lease" "$STUB_SSH_TEXT" || bad "the lease read is not an always-array JSON"
grep -qF -- "-Depth 3" "$STUB_SSH_TEXT" || bad "the JSON depth is not set"
[ "$(grep -c 'if (-not \$?) { exit 1 }' "$STUB_SSH_TEXT")" -eq 9 ] || bad "a recorded read can exit 0 after an error"
grep -qF -- "-EncodedCommand" "$STUB_LOG" || bad "commands do not travel encoded"
if $B --record windows "$tmp/rec" >/dev/null 2>&1; then bad "--record overwrote a directory with fixtures in it"; fi
if STUB_FAIL_ON=Get-Service $B --record windows "$tmp/rec2" >/dev/null 2>&1; then bad "--record kept going after a failed read"; fi
[ ! -e "$tmp/rec2" ] || bad "a failed recording left a directory"

# --- up-source.sh: the seed is baked (lab #14) ---------------------------------
# No sidecar, no cell; with the current id the render path passes; the run
# path stops at the missing image before any VM.
rm -f "$LAB_IMAGE_CACHE/windows-2025-eval.build-id"
if UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh windows "$tmp/w" >"$tmp/o" 2>&1; then bad "up-source.sh render-only accepted a windows cell with no build id"; fi
grep -qF "run scripts/build-windows-image.sh windows" "$tmp/o" || bad "the missing build id is not worded: $(cat "$tmp/o")"
printf '%s\n' "$id" >"$LAB_IMAGE_CACHE/windows-2025-eval.build-id"
if ! UP_SOURCE_RENDER_ONLY=1 ./scripts/up-source.sh windows "$tmp/w" >"$tmp/o" 2>&1; then bad "up-source.sh render-only refused the windows seed: $(cat "$tmp/o")"; fi
: >"$STUB_LOG"
if ./scripts/up-source.sh windows "$tmp/w2" >"$tmp/o" 2>&1; then bad "up-source.sh brought a windows cell up without its image"; fi
grep -qF "is a built image and is not there" "$tmp/o" || bad "the run-path refusal is not worded: $(cat "$tmp/o")"
grep -q '^virt-install' "$STUB_LOG" && bad "up-source.sh started a VM without the image"
[ ! -e "$tmp/w2/lab-windows-source.qcow2" ] || bad "the refused run path made an overlay"

[ "$fail" -eq 0 ] && echo "build-windows-image-test: PASS"
exit "$fail"
