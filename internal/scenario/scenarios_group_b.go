package scenario

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// Group B (#23): router-side features. Every verdict reads the source's
// own table or the source's own DNS answer, never the plugin's log. A
// scenario that needs a network option runs on its own network
// <e.Network>-bN, removed by a defer whatever the outcome; the cell's
// main network is never changed.

const (
	// b6Wait bounds how long B6 waits for the table's expiry to move:
	// dnsmasq raises any lease under two minutes to two minutes
	// (dnsmasq(8)), so a renewal at about half of that needs room.
	b6Wait = 3 * time.Minute
	// b7Wait bounds how long B7 waits for the source to show the lease
	// gone: with release_lease=on_remove the release leaves 65-80 s
	// after the remove (plugin docs/reference.md, tombstone window).
	b7Wait   = 150 * time.Second
	bPollGap = 5 * time.Second
)

// bCleanupCtx outlives a cancelled scenario context, so the network and
// container removal in a defer still runs after a timeout.
func bCleanupCtx(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

// bNetwork creates the scenario's own network and returns the func that
// removes it. down is never nil, so a caller defers it before looking at
// err and a half-made network is removed too (defeat list 1).
func bNetwork(ctx context.Context, e Env, n int, opts []string) (net string, down func(), err error) {
	suffix := "b" + strconv.Itoa(n)
	down = func() { NetworkDownExtra(bCleanupCtx(ctx), e.Host, e.Network, suffix) }
	net, err = NetworkUpExtra(ctx, e.Host, e.Network, e.Shape, suffix, opts)
	return net, down, err
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func leasesForMAC(leases []sourceadapter.Lease, mac string) []sourceadapter.Lease {
	var out []sourceadapter.Lease
	for _, l := range leases {
		if strings.EqualFold(l.MAC, mac) {
			out = append(out, l)
		}
	}
	return out
}

// runB1 -- reservation by MAC: a container with a fixed MAC that the
// source reserves an address for must get exactly that address.
func runB1(ctx context.Context, e Env) Verdict {
	if e.Shape == ShapeIpvlan {
		return na(NameB1, e.Cell, e.Shape, "ipvlan containers share the parent NIC's MAC; a reservation by MAC is not meaningful here", e.GitSHA)
	}
	reserved, err := reservationAddr(e, NameB1)
	if err != nil {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("no usable reservation address: %v", err), nil, e.GitSHA)
	}
	fixedMAC := fixedMACForScenario(e.Cell, e.Shape, "b1")
	if err := e.Source.ReserveMAC(ctx, fixedMAC, reserved); err != nil {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("could not reserve %s for %s on the source: %v", reserved, fixedMAC, err), nil, e.GitSHA)
	}
	name := containerName(e, NameB1)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, endpointID, err := runContainerFixedMAC(ctx, e.Host, e.Shape, e.Network, name, "", fixedMAC)
	if err != nil {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	snap := evidencePath(e, NameB1, "leases-after")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, reserved, endpointID, snap)
	if err != nil {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if addr != reserved {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("container mac %s got %s, the source reserved %s for it", mac, addr, reserved), ev, e.GitSHA)
	}
	if !ok {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("container reports %s but the source's table has no lease of %s to mac %s", addr, reserved, mac), ev, e.GitSHA)
	}
	secs, err := reachableWithRetry(ctx, e.Source, addr)
	if err != nil {
		return fail(NameB1, e.Cell, e.Shape, fmt.Sprintf("mac %s leased the reserved %s, but the source could not reach it within %ds: %v", mac, addr, secs, err), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameB1, "capture-check")
	return pass(NameB1, e.Cell, e.Shape, fmt.Sprintf("mac %s got the reserved address %s, leased to it in the source's own table, reachable after %ds", mac, addr, secs), ev, e.GitSHA)
}

// b2ClientID is the client_id string B2 sets; the plugin sends it as
// option 61 behind a 0x00 type byte (plugin docs/reference.md).
func b2ClientID(shape Shape) string { return "lab-b2-" + string(shape) }

// b2WireClientID is b2ClientID as the source's table spells it.
func b2WireClientID(id string) string { return hexColonID(append([]byte{0}, id...)) }

// runB2 -- reservation by client id: the network sets client_id, the
// source reserves an address for that option 61 value, the container
// must get it.
func runB2(ctx context.Context, e Env) Verdict {
	reserved, err := reservationAddr(e, NameB2)
	if err != nil {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("no usable reservation address: %v", err), nil, e.GitSHA)
	}
	id := b2ClientID(e.Shape)
	wire := b2WireClientID(id)
	if err := e.Source.ReserveClientID(ctx, wire, reserved); err != nil {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("could not reserve %s for client id %s on the source: %v", reserved, wire, err), nil, e.GitSHA)
	}
	net, down, err := bNetwork(ctx, e, 2, []string{"client_id=" + id})
	defer down()
	if err != nil {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("could not create the client_id network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameB2)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, _, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	snap := evidencePath(e, NameB2, "leases-after")
	lease, _, ok, err := lookupLeaseByClientID(ctx, e.Source, wire, snap)
	if err != nil {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("no lease under client id %s in the source's own table (container reports %s)", wire, addr), ev, e.GitSHA)
	}
	if lease.Address != reserved || addr != reserved {
		return fail(NameB2, e.Cell, e.Shape, fmt.Sprintf("client id %s was reserved %s, the table shows %s and the container reports %s", wire, reserved, lease.Address, addr), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameB2, "capture-check")
	return pass(NameB2, e.Cell, e.Shape, fmt.Sprintf("client id %s (client_id=%s) got the reserved address %s, shown under that id in the source's own table", wire, id, addr), ev, e.GitSHA)
}

var ipv4TokenRE = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// dnsAnswerAddrs returns the IPv4 addresses a busybox nslookup printed
// after its "Name:" line, so the "Server:/Address:" header naming the
// queried server is never read as an answer.
func dnsAnswerAddrs(out string) []string {
	i := strings.Index(out, "Name:")
	if i < 0 {
		return nil
	}
	return ipv4TokenRE.FindAllString(out[i:], -1)
}

// b3Hostname is the container hostname B3 registers.
func b3Hostname(e Env) string { return fmt.Sprintf("labb3-%s-%s", e.Cell, e.Shape) }

// runB3 -- DNS registration: with register_dns=true the source answers a
// query for the container's hostname with its leased address. The query
// runs inside the container and names the source's segment address as
// the server, so the answer cannot come from any other resolver.
func runB3(ctx context.Context, e Env) Verdict {
	return runB3Tuned(ctx, e, 10, 2*time.Second)
}

func runB3Tuned(ctx context.Context, e Env, tries int, gap time.Duration) Verdict {
	if _, err := netip.ParseAddr(e.SegGateway); err != nil {
		return fail(NameB3, e.Cell, e.Shape, fmt.Sprintf("no source segment address to query (%q): %v", e.SegGateway, err), nil, e.GitSHA)
	}
	net, down, err := bNetwork(ctx, e, 3, []string{"register_dns=true"})
	defer down()
	if err != nil {
		return fail(NameB3, e.Cell, e.Shape, fmt.Sprintf("could not create the register_dns network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameB3)
	host := b3Hostname(e)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, endpointID, err := runContainerWith(ctx, e.Host, e.Shape, net, name, "--hostname "+host)
	if err != nil {
		return fail(NameB3, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	snap := evidencePath(e, NameB3, "leases-after")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameB3, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok {
		return fail(NameB3, e.Cell, e.Shape, leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	query := fmt.Sprintf("sudo docker exec %s nslookup %s %s", name, host, e.SegGateway)
	var out string
	var answers []string
	for i := 0; i < tries; i++ {
		out, _ = e.Host.Run(ctx, query)
		if answers = dnsAnswerAddrs(out); len(answers) > 0 {
			break
		}
		if err := sleepCtx(ctx, gap); err != nil {
			return fail(NameB3, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
		}
	}
	dnsPath := evidencePath(e, NameB3, "dns-answer")
	if err := os.WriteFile(dnsPath, []byte("# "+query+"\n"+out), 0o644); err == nil {
		ev["dns-answer"] = dnsPath
	}
	for _, a := range answers {
		if a == addr {
			return pass(NameB3, e.Cell, e.Shape, fmt.Sprintf("the source at %s answers %s with the leased address %s", e.SegGateway, host, addr), ev, e.GitSHA)
		}
	}
	return fail(NameB3, e.Cell, e.Shape, fmt.Sprintf("the source at %s answered %s with %v, want the leased address %s", e.SegGateway, host, answers, addr), ev, e.GitSHA)
}

// runB4 -- requested address kept: a fixed-MAC container is removed (the
// default release_lease=never keeps the lease) and a new container with
// the same MAC must get the same address, from the same single lease.
func runB4(ctx context.Context, e Env) Verdict {
	if e.Shape == ShapeIpvlan {
		return na(NameB4, e.Cell, e.Shape, "ipvlan containers share the parent NIC's MAC; a fixed mac_address is not meaningful here", e.GitSHA)
	}
	name := containerName(e, NameB4)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)
	fixedMAC := fixedMACForScenario(e.Cell, e.Shape, "b4")

	mac, addr, endpointID, err := runContainerFixedMAC(ctx, e.Host, e.Shape, e.Network, name, "", fixedMAC)
	if err != nil {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("first container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameB4, "leases-before")
	_, before, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameB4, e.Cell, e.Shape, "first container: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}
	if n := len(leasesForMAC(before, mac)); n != 1 {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("before the remove the table already holds %d leases for mac %s, want 1", n, mac), evBefore, e.GitSHA)
	}
	removeContainer(ctx, e.Host, name)

	mac2, addr2, endpointID2, err := runContainerFixedMAC(ctx, e.Host, e.Shape, e.Network, name, "", fixedMAC)
	if err != nil {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("second container did not start: %v", err), evBefore, e.GitSHA)
	}
	afterSnap := evidencePath(e, NameB4, "leases-after")
	_, after, ok, err := lookupLease(ctx, e.Source, e.Shape, mac2, addr2, endpointID2, afterSnap)
	if err != nil {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after the second start: %v", err), evBefore, e.GitSHA)
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after": afterSnap}
	if addr2 != addr {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("mac %s had %s, the second container with the same mac got %s", mac, addr, addr2), ev, e.GitSHA)
	}
	if !ok {
		return fail(NameB4, e.Cell, e.Shape, "second container: "+leaseFailReason(e.Shape, mac2, addr2, endpointID2), ev, e.GitSHA)
	}
	if n := len(leasesForMAC(after, mac)); n != 1 {
		return fail(NameB4, e.Cell, e.Shape, fmt.Sprintf("the table holds %d leases for mac %s after the second start, want exactly 1 (a fresh lease that happens to equal %s is not the same lease)", n, mac, addr), ev, e.GitSHA)
	}
	return pass(NameB4, e.Cell, e.Shape, fmt.Sprintf("mac %s kept %s across a remove and a new container, one lease for the mac in the source's own table before and after", mac, addr), ev, e.GitSHA)
}

// vendorClass is the option 60 value B5 sets and the source classifies.
const vendorClass = "lab-class-b5"

// runB5 -- vendor class: with vendor_class set, the source serves the
// container from the class pool, outside the main pool.
func runB5(ctx context.Context, e Env) Verdict {
	first, last, err := classPool(e)
	if err != nil {
		return fail(NameB5, e.Cell, e.Shape, fmt.Sprintf("no usable class pool: %v", err), nil, e.GitSHA)
	}
	net, down, err := bNetwork(ctx, e, 5, []string{"vendor_class=" + vendorClass})
	defer down()
	if err != nil {
		return fail(NameB5, e.Cell, e.Shape, fmt.Sprintf("could not create the vendor_class network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameB5)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameB5, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	snap := evidencePath(e, NameB5, "leases-after")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, snap)
	if err != nil {
		return fail(NameB5, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	if !ok {
		return fail(NameB5, e.Cell, e.Shape, leaseFailReason(e.Shape, mac, addr, endpointID), ev, e.GitSHA)
	}
	in, err := inClassPool(e, addr)
	if err != nil {
		return fail(NameB5, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
	}
	if !in {
		return fail(NameB5, e.Cell, e.Shape, fmt.Sprintf("address %s is outside the class pool %s-%s (a source VM built before the class pool existed has to be rebuilt)", addr, first, last), ev, e.GitSHA)
	}
	corroborate(ctx, e, mac, ev, NameB5, "capture-check")
	return pass(NameB5, e.Cell, e.Shape, fmt.Sprintf("vendor_class=%s got %s from the class pool %s-%s, confirmed in the source's own table", vendorClass, addr, first, last), ev, e.GitSHA)
}

func nameserverIn(resolv, want string) bool {
	for _, line := range strings.Split(resolv, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" && f[1] == want {
			return true
		}
	}
	return false
}

// runB6 -- option change on renewal: after the first lease the source's
// DNS option changes; once the table shows the lease renewed, the
// container's resolv.conf must carry the new server.
func runB6(ctx context.Context, e Env) Verdict {
	return runB6Tuned(ctx, e, a14LeaseSeconds, b6Wait, bPollGap)
}

func runB6Tuned(ctx context.Context, e Env, leaseSeconds int, wait, poll time.Duration) Verdict {
	newDNS, err := groupBAddr(e, dnsOptionHost)
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("no usable DNS address: %v", err), nil, e.GitSHA)
	}
	restoreShort, err := e.Source.ShortenLeaseTime(ctx, leaseSeconds)
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not shorten the source's lease time: %v", err), nil, e.GitSHA)
	}
	defer restoreShort(bCleanupCtx(ctx))

	net, down, err := bNetwork(ctx, e, 6, []string{"propagate_dns=true"})
	defer down()
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not create the propagate_dns network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameB6)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameB6, "leases-before")
	first, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameB6, e.Cell, e.Shape, "before the change: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}
	if first.Expires.IsZero() {
		return fail(NameB6, e.Cell, e.Shape, "the source's table carries no expiry for the lease, so a renewal cannot be seen", evBefore, e.GitSHA)
	}
	resolvBefore, err := e.Host.Run(ctx, fmt.Sprintf("sudo docker exec %s cat /etc/resolv.conf", name))
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not read resolv.conf before the change: %v", err), evBefore, e.GitSHA)
	}
	if nameserverIn(resolvBefore, newDNS) {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("resolv.conf already names %s before the source offers it", newDNS), evBefore, e.GitSHA)
	}
	restoreDNS, err := e.Source.SetDNSOption(ctx, newDNS)
	if err != nil {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not change the source's DNS option: %v", err), evBefore, e.GitSHA)
	}
	defer restoreDNS(bCleanupCtx(ctx))

	// The verdict waits for the table's expiry to move, never for a
	// fixed time: a resolv.conf read before the renewal would see the
	// old server and mean nothing (defeat list 4).
	afterSnap := evidencePath(e, NameB6, "leases-after-renewal")
	deadline := time.Now().Add(wait)
	renewed := false
	for {
		l, _, found, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
		if err != nil {
			return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table while waiting for the renewal: %v", err), evBefore, e.GitSHA)
		}
		if found && l.Expires.After(first.Expires) {
			renewed = true
			break
		}
		if time.Now().After(deadline) {
			break
		}
		if err := sleepCtx(ctx, poll); err != nil {
			return fail(NameB6, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
		}
	}
	ev := map[string]string{"leases-before": beforeSnap, "leases-after-renewal": afterSnap}
	if !renewed {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("the table's expiry for %s did not move past %s within %s, so no renewal was seen", addr, first.Expires.Format(time.RFC3339), wait), ev, e.GitSHA)
	}
	var resolvAfter string
	for i := 0; i < 6; i++ {
		resolvAfter, err = e.Host.Run(ctx, fmt.Sprintf("sudo docker exec %s cat /etc/resolv.conf", name))
		if err == nil && nameserverIn(resolvAfter, newDNS) {
			break
		}
		if err := sleepCtx(ctx, poll/5); err != nil {
			break
		}
	}
	resolvPath := evidencePath(e, NameB6, "resolv-conf")
	note := fmt.Sprintf("# before the change\n%s\n# after the renewal\n%s\n", resolvBefore, resolvAfter)
	if werr := os.WriteFile(resolvPath, []byte(note), 0o644); werr == nil {
		ev["resolv-conf"] = resolvPath
	}
	if !nameserverIn(resolvAfter, newDNS) {
		return fail(NameB6, e.Cell, e.Shape, fmt.Sprintf("the lease renewed but resolv.conf does not carry the new DNS server %s", newDNS), ev, e.GitSHA)
	}
	return pass(NameB6, e.Cell, e.Shape, fmt.Sprintf("after the source changed its DNS option and the table showed %s renewed, resolv.conf carries %s", addr, newDNS), ev, e.GitSHA)
}

// runB7 -- lease release: with release_lease=on_remove, removing the
// container makes the source's table stop showing the lease. The
// adapters return active leases only, so absence means released.
func runB7(ctx context.Context, e Env) Verdict {
	return runB7Tuned(ctx, e, b7Wait, bPollGap)
}

func runB7Tuned(ctx context.Context, e Env, wait, poll time.Duration) Verdict {
	net, down, err := bNetwork(ctx, e, 7, []string{"release_lease=on_remove"})
	defer down()
	if err != nil {
		return fail(NameB7, e.Cell, e.Shape, fmt.Sprintf("could not create the release_lease network: %v", err), nil, e.GitSHA)
	}
	name := containerName(e, NameB7)
	defer removeContainer(bCleanupCtx(ctx), e.Host, name)

	mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, net, name)
	if err != nil {
		return fail(NameB7, e.Cell, e.Shape, fmt.Sprintf("container did not start: %v", err), nil, e.GitSHA)
	}
	beforeSnap := evidencePath(e, NameB7, "leases-before")
	_, _, ok, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, beforeSnap)
	if err != nil {
		return fail(NameB7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	evBefore := map[string]string{"leases-before": beforeSnap}
	if !ok {
		return fail(NameB7, e.Cell, e.Shape, "before the remove: "+leaseFailReason(e.Shape, mac, addr, endpointID), evBefore, e.GitSHA)
	}
	removeContainer(ctx, e.Host, name)

	afterSnap := evidencePath(e, NameB7, "leases-after-remove")
	start := time.Now()
	deadline := start.Add(wait)
	for {
		_, _, still, err := lookupLease(ctx, e.Source, e.Shape, mac, addr, endpointID, afterSnap)
		if err != nil {
			return fail(NameB7, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table after the remove: %v", err), evBefore, e.GitSHA)
		}
		ev := map[string]string{"leases-before": beforeSnap, "leases-after-remove": afterSnap}
		if !still {
			return pass(NameB7, e.Cell, e.Shape, fmt.Sprintf("%s no longer shows an active lease for %s %ds after the remove", "the source's table", addr, int(time.Since(start).Round(time.Second)/time.Second)), ev, e.GitSHA)
		}
		if time.Now().After(deadline) {
			return fail(NameB7, e.Cell, e.Shape, fmt.Sprintf("the source's table still shows an active lease for %s %s after the remove (the release leaves 65-80 s after it)", addr, wait), ev, e.GitSHA)
		}
		if err := sleepCtx(ctx, poll); err != nil {
			return fail(NameB7, e.Cell, e.Shape, err.Error(), evBefore, e.GitSHA)
		}
	}
}

// runB8 -- three containers at once on the cell's network: three
// distinct leases; under ipvlan they share one MAC and differ by
// client id, which is what keeps them apart.
func runB8(ctx context.Context, e Env) Verdict {
	const n = 3
	type created struct{ name, mac, addr, endpointID string }
	var containers []created
	defer func() {
		for _, c := range containers {
			removeContainer(bCleanupCtx(ctx), e.Host, c.name)
		}
	}()
	for i := 0; i < n; i++ {
		name := containerName(e, NameB8) + "-" + strconv.Itoa(i)
		mac, addr, endpointID, err := runContainer(ctx, e.Host, e.Shape, e.Network, name)
		containers = append(containers, created{name, mac, addr, endpointID})
		if err != nil {
			return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("container %d/%d (%s) did not start: %v", i+1, n, name, err), nil, e.GitSHA)
		}
	}
	snap := evidencePath(e, NameB8, "leases-after")
	leases, err := writeLeaseSnapshot(ctx, e.Source, snap)
	if err != nil {
		return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("could not read source lease table: %v", err), nil, e.GitSHA)
	}
	ev := map[string]string{"leases-after": snap}
	addrs := map[string]bool{}
	macs := map[string]bool{}
	clientIDs := map[string]bool{}
	for _, c := range containers {
		var l sourceadapter.Lease
		var ok bool
		if e.Shape == ShapeIpvlan {
			cid, err := ipvlanClientID(c.endpointID)
			if err != nil {
				return fail(NameB8, e.Cell, e.Shape, err.Error(), ev, e.GitSHA)
			}
			l, ok = findLeaseByClientID(leases, cid)
		} else {
			l, ok = findLease(leases, c.mac, c.addr)
		}
		if !ok {
			return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("%s: %s", c.name, leaseFailReason(e.Shape, c.mac, c.addr, c.endpointID)), ev, e.GitSHA)
		}
		addrs[l.Address] = true
		macs[strings.ToLower(l.MAC)] = true
		clientIDs[l.ClientID] = true
	}
	if len(addrs) != n {
		return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("%d containers share only %d distinct leased addresses", n, len(addrs)), ev, e.GitSHA)
	}
	if e.Shape == ShapeIpvlan {
		// The client ids are distinct by construction: each lease was
		// found by its own endpoint-derived id above.
		if len(macs) != 1 {
			return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("ipvlan: want one shared mac in the table, got %d", len(macs)), ev, e.GitSHA)
		}
		return pass(NameB8, e.Cell, e.Shape, fmt.Sprintf("%d containers on one shared mac hold %d distinct leases told apart by %d distinct client ids in the source's own table", n, len(addrs), len(clientIDs)), ev, e.GitSHA)
	}
	if len(macs) != n {
		return fail(NameB8, e.Cell, e.Shape, fmt.Sprintf("want %d distinct macs, the table shows %d", n, len(macs)), ev, e.GitSHA)
	}
	return pass(NameB8, e.Cell, e.Shape, fmt.Sprintf("%d containers hold %d distinct leases on %d distinct macs in the source's own table", n, len(addrs), len(macs)), ev, e.GitSHA)
}
