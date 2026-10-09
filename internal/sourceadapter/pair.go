package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PairPeer is one server of a failover pair (lab #12): its own adapter,
// the server identifier (option 54) it sends, and its HA state reader.
type PairPeer struct {
	Name     string
	Adapter  Adapter
	ServerID string
	State    func(ctx context.Context) (HAState, error)
}

// PairAdapter drives a failover pair as one source: every mutating call
// fans out to both peers, and Ready also needs both peers in Normal.
type PairAdapter struct {
	Peers  [2]PairPeer
	Normal string
	// Survivor is the state a peer reaches when its partner is down;
	// StandbySilent says the standby answers no DHCP while the primary
	// runs (Kea hot-standby, measured locally, lab #12).
	Survivor      string
	StandbySilent bool
	// NormalWait bounds the wait for Normal after a start; measured
	// locally at 4.8 s for Kea from a cold start (lab #12).
	NormalWait time.Duration
	NormalPoll time.Duration
}

// PairControl reaches one peer of a pair at a time, for the C5 family
// (lab #12). Peer names are PairPeer.Name.
type PairControl interface {
	PeerNames() []string
	PeerServerID(name string) (string, error)
	StopPeer(ctx context.Context, name string) error
	StartPeer(ctx context.Context, name string) error
	PeerLeases(ctx context.Context, name string) ([]Lease, error)
	PeerState(ctx context.Context, name string) (HAState, error)
	Profile() PairProfile
}

// PairProfile is what the C5 family needs to know about a pair's kind.
type PairProfile struct {
	Normal, Survivor string
	StandbySilent    bool
}

// NAExplainer lets an adapter say why it leaves a capability out, so the
// N/A verdict carries the reason instead of a bare capability name.
type NAExplainer interface {
	NAReason(c Capability) (string, bool)
}

var (
	_ Adapter     = (*PairAdapter)(nil)
	_ PairControl = (*PairAdapter)(nil)
	_ NAExplainer = (*PairAdapter)(nil)
)

// NewKeaPair builds the kea-ha cell's adapter from one runner per peer.
func NewKeaPair(primary, partner Runner, primaryID, partnerID string) *PairAdapter {
	peer := func(name string, r Runner, id string) PairPeer {
		return PairPeer{Name: name, Adapter: &KeaAdapter{Runner: r}, ServerID: id,
			State: func(ctx context.Context) (HAState, error) { return KeaHAState(ctx, r) }}
	}
	return &PairAdapter{
		Peers:         [2]PairPeer{peer("primary", primary, primaryID), peer("partner", partner, partnerID)},
		Normal:        KeaHotStandby,
		Survivor:      KeaPartnerDown,
		StandbySilent: true,
		NormalWait:    60 * time.Second,
		NormalPoll:    time.Second,
	}
}

// Capabilities is what both peers declare, plus CapFailoverPair, minus
// CapImpair (see NAReason).
func (p *PairAdapter) Capabilities() []Capability {
	second := map[Capability]bool{}
	for _, c := range p.Peers[1].Adapter.Capabilities() {
		second[c] = true
	}
	var out []Capability
	for _, c := range p.Peers[0].Adapter.Capabilities() {
		if second[c] && c != CapImpair && c != CapFailoverPair {
			out = append(out, c)
		}
	}
	return append(out, CapFailoverPair)
}

func (p *PairAdapter) NAReason(c Capability) (string, bool) {
	if c != CapImpair {
		return "", false
	}
	return "the pair's HA channel shares the segment leg: netem on it delays the heartbeat up to 10 s against " +
		"max-response-delay 6 s, both peers go partner-down, and the verdict would judge a split brain, " +
		"not the plugin; the single-server cells carry C10 (claymore666/docker-net-dhcp-lab#12)", true
}

// Leases is the union of the peers' tables, one entry per (address,
// identity) with the latest Expires; two identities on one address stay
// two entries. It fails only when no peer answers.
func (p *PairAdapter) Leases(ctx context.Context) ([]Lease, error) {
	type key struct{ addr, ident string }
	idx := map[key]int{}
	var out []Lease
	var errs []error
	read := 0
	for _, peer := range p.Peers {
		ls, err := peer.Adapter.Leases(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", peer.Name, err))
			continue
		}
		read++
		for _, l := range ls {
			id := l.ClientID
			if id == "" {
				id = l.MAC
			}
			k := key{l.Address, id}
			if i, ok := idx[k]; ok {
				if l.Expires.After(out[i].Expires) {
					out[i] = l
				}
				continue
			}
			idx[k] = len(out)
			out = append(out, l)
		}
	}
	if read == 0 {
		return nil, fmt.Errorf("pair: no peer table readable: %w", errors.Join(errs...))
	}
	return out, nil
}

// ReserveMAC and ReserveClientID have no undo in the Adapter interface:
// a partner failure leaves the primary's reservation, which the next
// ResetLeases or Recover clears; the error names the failing peer.
func (p *PairAdapter) ReserveMAC(ctx context.Context, mac, addr string) error {
	return p.each(func(a Adapter) error { return a.ReserveMAC(ctx, mac, addr) })
}

func (p *PairAdapter) ReserveClientID(ctx context.Context, clientID, addr string) error {
	return p.each(func(a Adapter) error { return a.ReserveClientID(ctx, clientID, addr) })
}

func (p *PairAdapter) each(f func(Adapter) error) error {
	for _, peer := range p.Peers {
		if err := f(peer.Adapter); err != nil {
			return fmt.Errorf("pair: %s: %w", peer.Name, err)
		}
	}
	return nil
}

// fanOut applies one restorable change to both peers. A failure on the
// second runs the first's restore; the returned restore runs both in
// reverse order and then waits for Normal.
func (p *PairAdapter) fanOut(ctx context.Context, f func(Adapter) (func(context.Context) error, error)) (func(context.Context) error, error) {
	var restores []func(context.Context) error
	undo := func(ctx context.Context) error {
		var errs []error
		for i := len(restores) - 1; i >= 0; i-- {
			if err := restores[i](ctx); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", p.Peers[i].Name, err))
			}
		}
		return errors.Join(errs...)
	}
	for _, peer := range p.Peers {
		r, err := f(peer.Adapter)
		if err != nil {
			err = fmt.Errorf("pair: %s: %w", peer.Name, err)
			if uerr := undo(ctx); uerr != nil {
				err = errors.Join(err, uerr)
			}
			return nil, err
		}
		restores = append(restores, r)
	}
	if err := p.waitNormal(ctx); err != nil {
		return nil, errors.Join(err, undo(ctx))
	}
	return func(ctx context.Context) error {
		if err := undo(ctx); err != nil {
			return err
		}
		return p.waitNormal(ctx)
	}, nil
}

func (p *PairAdapter) SetDNSOption(ctx context.Context, addr string) (func(context.Context) error, error) {
	return p.fanOut(ctx, func(a Adapter) (func(context.Context) error, error) { return a.SetDNSOption(ctx, addr) })
}

func (p *PairAdapter) ShortenLeaseTime(ctx context.Context, seconds int) (func(context.Context) error, error) {
	return p.fanOut(ctx, func(a Adapter) (func(context.Context) error, error) { return a.ShortenLeaseTime(ctx, seconds) })
}

func (p *PairAdapter) EnableFeature(ctx context.Context, f Feature, fp FeatureParams) (func(context.Context) error, error) {
	return p.fanOut(ctx, func(a Adapter) (func(context.Context) error, error) { return a.EnableFeature(ctx, f, fp) })
}

// Stop stops both peers: the whole DHCP service is down, as C1-C3 need.
// A partner failure starts the primary again.
func (p *PairAdapter) Stop(ctx context.Context) error {
	if err := p.Peers[0].Adapter.Stop(ctx); err != nil {
		return fmt.Errorf("pair: %s: %w", p.Peers[0].Name, err)
	}
	if err := p.Peers[1].Adapter.Stop(ctx); err != nil {
		err = fmt.Errorf("pair: %s: %w", p.Peers[1].Name, err)
		return errors.Join(err, p.Peers[0].Adapter.Start(ctx))
	}
	return nil
}

// Start starts both peers and waits for Normal. A partner failure stops
// the primary again, so the pair is left as the call found it.
func (p *PairAdapter) Start(ctx context.Context) error {
	if err := p.Peers[0].Adapter.Start(ctx); err != nil {
		return fmt.Errorf("pair: %s: %w", p.Peers[0].Name, err)
	}
	if err := p.Peers[1].Adapter.Start(ctx); err != nil {
		err = fmt.Errorf("pair: %s: %w", p.Peers[1].Name, err)
		return errors.Join(err, p.Peers[0].Adapter.Stop(ctx))
	}
	return p.waitNormal(ctx)
}

func (p *PairAdapter) Restart(ctx context.Context) error {
	if err := p.each(func(a Adapter) error { return a.Restart(ctx) }); err != nil {
		return err
	}
	return p.waitNormal(ctx)
}

// Reachable pings from the primary's VM and falls back to the partner's:
// both sit on the segment whether or not their service runs.
func (p *PairAdapter) Reachable(ctx context.Context, addr string) error {
	err0 := p.Peers[0].Adapter.Reachable(ctx, addr)
	if err0 == nil {
		return nil
	}
	if err1 := p.Peers[1].Adapter.Reachable(ctx, addr); err1 != nil {
		return fmt.Errorf("pair: %s: %v; %s: %w", p.Peers[0].Name, err0, p.Peers[1].Name, err1)
	}
	return nil
}

// ResetLeases stops both peers before clearing either, so a reset peer
// cannot pull its partner's old table back through the HA sync.
func (p *PairAdapter) ResetLeases(ctx context.Context) error {
	if err := p.Stop(ctx); err != nil {
		return err
	}
	if err := p.each(func(a Adapter) error { return a.ResetLeases(ctx) }); err != nil {
		return err
	}
	return p.waitNormal(ctx)
}

func (p *PairAdapter) Ready(ctx context.Context) error {
	if err := p.each(func(a Adapter) error { return a.Ready(ctx) }); err != nil {
		return err
	}
	for _, peer := range p.Peers {
		st, err := peer.State(ctx)
		if err != nil {
			return fmt.Errorf("pair: %s: %w", peer.Name, err)
		}
		if st.State != p.Normal {
			return fmt.Errorf("pair: %s is in HA state %q, not %q", peer.Name, st.State, p.Normal)
		}
	}
	return nil
}

// Recover runs both peers' Recover, even when the first fails, then
// waits for Normal.
func (p *PairAdapter) Recover(ctx context.Context) error {
	var errs []error
	for _, peer := range p.Peers {
		if err := peer.Adapter.Recover(ctx); err != nil {
			errs = append(errs, fmt.Errorf("pair: %s: %w", peer.Name, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return p.waitNormal(ctx)
}

func (p *PairAdapter) Impair(ctx context.Context, delay time.Duration, lossPct int) (func(context.Context) error, error) {
	return nil, errors.New("pair: impair is not offered on a failover pair (see NAReason)")
}

// SendForceRenew goes out from the peer whose server identifier the
// frame claims, so the client sees it come from its own server.
func (p *PairAdapter) SendForceRenew(ctx context.Context, script []byte, fp ForceRenewParams) (string, error) {
	peer, err := p.byServerID(fp.Server)
	if err != nil {
		return "", err
	}
	return peer.Adapter.SendForceRenew(ctx, script, fp)
}

func (p *PairAdapter) byServerID(id string) (*PairPeer, error) {
	for i := range p.Peers {
		if p.Peers[i].ServerID == id {
			return &p.Peers[i], nil
		}
	}
	return nil, fmt.Errorf("pair: server identifier %q is neither peer's (%s, %s)", id, p.Peers[0].ServerID, p.Peers[1].ServerID)
}

func (p *PairAdapter) peer(name string) (*PairPeer, error) {
	for i := range p.Peers {
		if p.Peers[i].Name == name {
			return &p.Peers[i], nil
		}
	}
	return nil, fmt.Errorf("pair: no peer named %q", name)
}

// waitNormal polls both peers until each reports Normal or NormalWait
// runs out.
func (p *PairAdapter) waitNormal(ctx context.Context) error {
	deadline := time.Now().Add(p.NormalWait)
	for {
		var last []string
		normal := 0
		for _, peer := range p.Peers {
			st, err := peer.State(ctx)
			switch {
			case err != nil:
				last = append(last, fmt.Sprintf("%s: %v", peer.Name, err))
			case st.State == p.Normal:
				normal++
			default:
				last = append(last, fmt.Sprintf("%s: %s", peer.Name, st.State))
			}
		}
		if normal == len(p.Peers) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("pair: not both %q within %s: %v", p.Normal, p.NormalWait, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(p.NormalPoll):
		}
	}
}

func (p *PairAdapter) PeerNames() []string {
	return []string{p.Peers[0].Name, p.Peers[1].Name}
}

func (p *PairAdapter) PeerServerID(name string) (string, error) {
	peer, err := p.peer(name)
	if err != nil {
		return "", err
	}
	return peer.ServerID, nil
}

func (p *PairAdapter) StopPeer(ctx context.Context, name string) error {
	peer, err := p.peer(name)
	if err != nil {
		return err
	}
	return peer.Adapter.Stop(ctx)
}

func (p *PairAdapter) StartPeer(ctx context.Context, name string) error {
	peer, err := p.peer(name)
	if err != nil {
		return err
	}
	return peer.Adapter.Start(ctx)
}

func (p *PairAdapter) PeerLeases(ctx context.Context, name string) ([]Lease, error) {
	peer, err := p.peer(name)
	if err != nil {
		return nil, err
	}
	return peer.Adapter.Leases(ctx)
}

func (p *PairAdapter) PeerState(ctx context.Context, name string) (HAState, error) {
	peer, err := p.peer(name)
	if err != nil {
		return HAState{}, err
	}
	return peer.State(ctx)
}

func (p *PairAdapter) Profile() PairProfile {
	return PairProfile{Normal: p.Normal, Survivor: p.Survivor, StandbySilent: p.StandbySilent}
}
