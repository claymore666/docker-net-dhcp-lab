package sourceadapter

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Feature names one server-side setting a group F scenario needs (#20).
type Feature string

const (
	// FeatureUserClassPool serves Class's clients (option 77) from
	// PoolStart-PoolEnd and keeps the main pool away from them.
	FeatureUserClassPool Feature = "user-class-pool"
	// FeatureOffer108 sets option 108 on the subnet without forcing it,
	// so a client that never asks never receives it (F2a, RFC 8925 3.3).
	FeatureOffer108 Feature = "offer-108"
	// FeatureForce108 sends option 108 to ClientID's client even though
	// it did not ask, to show it ignores it (F2b, RFC 8925 3.2).
	FeatureForce108 Feature = "force-108"
	// FeatureRapidCommit4 turns DHCPv4 rapid commit on (group F, RFC 4039).
	FeatureRapidCommit4 Feature = "rapid-commit-4"
	// FeatureForceRenewNonce hands ClientID's client option 145 and, in
	// the ACK, an option 90 carrying Nonce, so a FORCERENEW signed with
	// it can be checked (F8-forcerenew, RFC 6704 3.1.2).
	FeatureForceRenewNonce Feature = "forcerenew-nonce"
	// FeatureRapidCommit6 answers a Solicit with option 14 by a Reply
	// (F4-rapid-commit-v6, RFC 8415 section 18.3.1).
	FeatureRapidCommit6 Feature = "rapid-commit-6"
	// FeatureTemporary6 grants IA_TA from the source's temp6_pool
	// (F5-temporary-address, RFC 8415 section 21.5).
	FeatureTemporary6 Feature = "temporary-6"
	// FeaturePD delegates /64s from FeatureParams.PDPool (RFC 8415
	// section 6.3): Kea pd-pools, ISC prefix6.
	FeaturePD Feature = "pd"
)

// ForceRenewNonceLen is the nonce length RFC 6704 3.1.2 fixes for
// HMAC-MD5 (algorithm 1).
const ForceRenewNonceLen = 16

// FeatureParams carries what a Feature needs; unused fields stay zero.
type FeatureParams struct {
	// Class is the option 77 text: letters, digits, dot, dash, underscore.
	Class              string
	PoolStart, PoolEnd string
	// Seconds is option 108's value (V6ONLY_WAIT), 1 to 4294967295.
	Seconds uint32
	// ClientID is the option 61 value as colon-hex, type byte included.
	ClientID string
	// Nonce is the FORCERENEW key, ForceRenewNonceLen bytes.
	Nonce []byte
	// PDPool is FeaturePD's pool: a ULA prefix of length 48 to 63.
	PDPool netip.Prefix
}

var userClassRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// validatedFeature is FeatureParams after every field a feature uses
// passed its guard; nothing else reaches a config or a shell.
type validatedFeature struct {
	Feature
	class, start, end, clientID string
	seconds                     uint32
	nonce                       []byte
	pdPool                      netip.Prefix
}

func validateFeature(f Feature, p FeatureParams) (validatedFeature, error) {
	v := validatedFeature{Feature: f}
	switch f {
	case FeatureUserClassPool:
		if !userClassRE.MatchString(p.Class) {
			return v, fmt.Errorf("invalid user class %q: want 1 to 64 of letters, digits, '.', '-', '_'", p.Class)
		}
		var err error
		if v.start, err = validateAddr(p.PoolStart); err != nil {
			return v, err
		}
		if v.end, err = validateAddr(p.PoolEnd); err != nil {
			return v, err
		}
		a, b := netip.MustParseAddr(v.start), netip.MustParseAddr(v.end)
		if a.Compare(b) > 0 {
			return v, fmt.Errorf("pool %s - %s is backwards", v.start, v.end)
		}
		v.class = p.Class
	case FeatureOffer108, FeatureForce108:
		if p.Seconds == 0 {
			return v, errors.New("option 108 needs a non-zero Seconds")
		}
		v.seconds = p.Seconds
		if f == FeatureForce108 {
			id, err := validateClientID(p.ClientID)
			if err != nil {
				return v, err
			}
			v.clientID = id
		}
	case FeatureRapidCommit4, FeatureRapidCommit6, FeatureTemporary6:
	case FeaturePD:
		pool, err := validateULA(p.PDPool, 48, 63)
		if err != nil {
			return v, fmt.Errorf("prefix delegation pool: %w", err)
		}
		v.pdPool = pool
	case FeatureForceRenewNonce:
		if len(p.Nonce) != ForceRenewNonceLen {
			return v, fmt.Errorf("forcerenew nonce is %d bytes, want %d", len(p.Nonce), ForceRenewNonceLen)
		}
		id, err := validateClientID(p.ClientID)
		if err != nil {
			return v, err
		}
		v.clientID, v.nonce = id, append([]byte(nil), p.Nonce...)
	default:
		return v, fmt.Errorf("unknown feature %q", f)
	}
	return v, nil
}

// hex108 is option 108's four value bytes as colon-hex.
func (v validatedFeature) hex108() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x", byte(v.seconds>>24), byte(v.seconds>>16), byte(v.seconds>>8), byte(v.seconds))
}

// ForceRenewNonceOption is the option 90 value a server hands out with
// nonce: protocol 3, algorithm 1 (HMAC-MD5), RDM 0, replay 1, type 1
// (nonce), the nonce (RFC 6704 3.1.2). The replay value 1 is the
// floor a FORCERENEW must exceed (RFC 3118 section 2).
func ForceRenewNonceOption(nonce []byte) []byte {
	b := []byte{3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}
	return append(b, nonce...)
}

// auth90Hex is option 90's value for v.nonce as colon-hex.
func (v validatedFeature) auth90Hex() string { return hexColon(ForceRenewNonceOption(v.nonce)) }

// classHex is option 77 as RFC 3004 encodes one instance: a length byte,
// then the text.
func (v validatedFeature) classHex() string {
	b := append([]byte{byte(len(v.class))}, v.class...)
	return hexColon(b)
}

// configEdit is one regexp substitution that must change the config.
type configEdit struct {
	re   *regexp.Regexp
	repl string
	what string
}

// enableFeatureViaSubstitution is every adapter's EnableFeature body
// (#20): capture the running config, refuse if it already carries the
// feature, apply each edit (each must change the text), write, restart.
// A failed write or restart puts the captured bytes back before the
// error returns; restore does the same on demand and tries the restart
// even when the write failed, so no path leaves the edit behind.
func enableFeatureViaSubstitution(ctx context.Context, r Runner, path, already string, edits []configEdit, restart func(context.Context) error, label string) (func(context.Context) error, error) {
	orig, err := r.Run(ctx, "sudo cat "+path)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s before enabling a feature: %w", label, path, err)
	}
	if strings.Contains(orig, already) {
		return nil, fmt.Errorf("%s: %s already carries %q; refusing to add it twice (Recover puts the baseline back)", label, path, already)
	}
	changed := orig
	for _, e := range edits {
		next := e.re.ReplaceAllString(changed, e.repl)
		if next == changed {
			return nil, fmt.Errorf("%s: anchor for %s not found in %s; refusing to change it blindly", label, e.what, path)
		}
		changed = next
	}
	restore := func(ctx context.Context) error {
		werr := writeRemoteConfig(ctx, r, path, orig)
		rerr := restart(ctx)
		if werr != nil {
			werr = fmt.Errorf("%s: restore original config to %s: %w", label, path, werr)
		}
		if rerr != nil {
			rerr = fmt.Errorf("%s: restart after restoring the config: %w", label, rerr)
		}
		return errors.Join(werr, rerr)
	}
	if err := writeRemoteConfig(ctx, r, path, changed); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: write feature config to %s: %w", label, path, err), restore(ctx))
	}
	if err := restart(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("%s: restart after enabling a feature: %w", label, err), restore(ctx))
	}
	return restore, nil
}

// hexPlain drops the colons of a colon-hex string.
func hexPlain(h string) string { return strings.ReplaceAll(h, ":", "") }
