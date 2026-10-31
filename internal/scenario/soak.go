package scenario

import (
	"fmt"
	"strconv"
	"time"
)

// The environment variables labctl run reads E5's parameters from.
const (
	SoakWindowEnv = "LAB_SOAK_DURATION"
	SoakLeaseEnv  = "LAB_SOAK_LEASE"
)

// Lab #15 asks for weeks at shipped lease times; a fixture run keeps the
// window short and the release run sets a longer one.
const (
	soakDefaultWindow = 3 * time.Minute
	soakDefaultLease  = 40
)

// SoakParams is E5's window and the lease time the source is shortened to.
type SoakParams struct {
	Window time.Duration
	Lease  int
}

// Resolved fills the defaults and refuses a window under two leases.
func (p SoakParams) Resolved() (SoakParams, error) {
	if p.Window == 0 {
		p.Window = soakDefaultWindow
	}
	if p.Lease == 0 {
		p.Lease = soakDefaultLease
	}
	if p.Window < 0 || p.Lease < 0 {
		return p, fmt.Errorf("soak window %s and lease %ds must be positive", p.Window, p.Lease)
	}
	if p.Window < 2*time.Duration(p.Lease)*time.Second {
		return p, fmt.Errorf("soak window %s is under two %ds leases, so no renewal would be required", p.Window, p.Lease)
	}
	return p, nil
}

// SoakFromEnv reads E5's parameters; a value that does not parse is an error, never the default.
func SoakFromEnv(getenv func(string) string) (SoakParams, error) {
	var p SoakParams
	if v := getenv(SoakWindowEnv); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return p, fmt.Errorf("%s=%q is not a positive Go duration such as 1h", SoakWindowEnv, v)
		}
		p.Window = d
	}
	if v := getenv(SoakLeaseEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return p, fmt.Errorf("%s=%q is not a positive number of seconds", SoakLeaseEnv, v)
		}
		p.Lease = n
	}
	return p.Resolved()
}
