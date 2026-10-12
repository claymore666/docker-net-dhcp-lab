package sourceadapter

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Until the TR-064 client lands (lab #13 PR 3) the adapter declares
// nothing and every method refuses with the same named error.
func TestFritzboxAdapterPlaceholderRefusesEverything(t *testing.T) {
	var a Adapter = &FritzboxAdapter{}
	if got := a.Capabilities(); len(got) != 0 {
		t.Fatalf("capabilities = %v, want none", got)
	}
	ctx := context.Background()
	errs := map[string]error{}
	_, errs["Leases"] = a.Leases(ctx)
	_, errs["Leases6"] = a.Leases6(ctx)
	_, errs["SetRA"] = a.SetRA(ctx, RAParams{})
	_, errs["StopV6Server"] = a.StopV6Server(ctx)
	errs["ReserveMAC"] = a.ReserveMAC(ctx, "02:00:00:00:00:01", "10.200.17.150")
	errs["ReserveClientID"] = a.ReserveClientID(ctx, "01:02", "10.200.17.150")
	_, errs["SetDNSOption"] = a.SetDNSOption(ctx, "10.200.17.1")
	errs["Restart"] = a.Restart(ctx)
	errs["Stop"] = a.Stop(ctx)
	errs["Start"] = a.Start(ctx)
	errs["Reachable"] = a.Reachable(ctx, "10.200.17.150")
	_, errs["ShortenLeaseTime"] = a.ShortenLeaseTime(ctx, 60)
	errs["ResetLeases"] = a.ResetLeases(ctx)
	errs["Ready"] = a.Ready(ctx)
	errs["Recover"] = a.Recover(ctx)
	_, errs["Impair"] = a.Impair(ctx, time.Second, 1)
	_, errs["EnableFeature"] = a.EnableFeature(ctx, Feature(""), FeatureParams{})
	_, errs["SendForceRenew"] = a.SendForceRenew(ctx, nil, ForceRenewParams{})
	_, errs["Squat"] = a.Squat(ctx, "10.200.17.150", false)
	_, errs["StartRogue"] = a.StartRogue(ctx, "10.200.17.240", "10.200.17.241", "10.200.17.245")
	_, errs["RogueLeases"] = a.RogueLeases(ctx)
	_, errs["NarrowPool"] = a.NarrowPool(ctx, "10.200.17.100", "10.200.17.110")
	_, errs["Renumber"] = a.Renumber(ctx, "10.200.117.0/24", "10.200.117.1/24", "10.200.117.100", "10.200.117.200")
	if len(errs) != 23 {
		t.Fatalf("exercised %d methods, the Adapter interface has 23 besides Capabilities", len(errs))
	}
	for name, err := range errs {
		if !errors.Is(err, errFritzboxPending) {
			t.Errorf("%s: %v, want errFritzboxPending", name, err)
		}
	}
}
