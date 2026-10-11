package sourceadapter

import (
	"context"
	"errors"
	"time"
)

// errFritzboxPending is every FritzboxAdapter method's answer until the
// TR-064 client lands (lab #13 PR 3). The adapter declares no capability,
// so no scenario reaches a method; a run on the cell stops at the first
// call instead of judging against a box nothing reads.
var errFritzboxPending = errors.New("fritzbox: no adapter yet; the TR-064 client is lab #13 PR 3")

// FritzboxAdapter is the placeholder newSourceAdapter returns for
// source.type fritzbox, so the shipped lab.yaml cell loads through the same
// path as every other cell (lab #13 PR 1).
type FritzboxAdapter struct{ Runner Runner }

func (*FritzboxAdapter) Capabilities() []Capability { return nil }

func (*FritzboxAdapter) Leases(context.Context) ([]Lease, error) { return nil, errFritzboxPending }

func (*FritzboxAdapter) Leases6(context.Context) ([]Lease6, error) { return nil, errFritzboxPending }

func (*FritzboxAdapter) SetRA(context.Context, RAParams) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) StopV6Server(context.Context) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) ReserveMAC(context.Context, string, string) error { return errFritzboxPending }

func (*FritzboxAdapter) ReserveClientID(context.Context, string, string) error {
	return errFritzboxPending
}

func (*FritzboxAdapter) SetDNSOption(context.Context, string) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) Restart(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Stop(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Start(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Reachable(context.Context, string) error { return errFritzboxPending }

func (*FritzboxAdapter) ShortenLeaseTime(context.Context, int) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) ResetLeases(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Ready(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Recover(context.Context) error { return errFritzboxPending }

func (*FritzboxAdapter) Impair(context.Context, time.Duration, int) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) EnableFeature(context.Context, Feature, FeatureParams) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) SendForceRenew(context.Context, []byte, ForceRenewParams) (string, error) {
	return "", errFritzboxPending
}

func (*FritzboxAdapter) Squat(context.Context, string, bool) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) StartRogue(context.Context, string, string, string) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) RogueLeases(context.Context) ([]Lease, error) { return nil, errFritzboxPending }

func (*FritzboxAdapter) NarrowPool(context.Context, string, string) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}

func (*FritzboxAdapter) Renumber(context.Context, string, string, string, string) (func(context.Context) error, error) {
	return nil, errFritzboxPending
}
