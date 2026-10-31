package scenario

import (
	"strings"
	"testing"
	"time"
)

func soakEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestSoakFromEnvDefaults(t *testing.T) {
	p, err := SoakFromEnv(soakEnv(nil))
	if err != nil || p.Window != 3*time.Minute || p.Lease != 40 {
		t.Fatalf("got %+v, %v; want the 3m window and 40s lease", p, err)
	}
}

func TestSoakFromEnvReadsBoth(t *testing.T) {
	p, err := SoakFromEnv(soakEnv(map[string]string{SoakWindowEnv: "1h", SoakLeaseEnv: "60"}))
	if err != nil || p.Window != time.Hour || p.Lease != 60 {
		t.Fatalf("got %+v, %v; want 1h and 60s", p, err)
	}
}

// Row 11: a value that does not parse, or a window under two leases, is
// an error, never the default.
func TestSoakFromEnvRefuses(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{SoakWindowEnv: "an hour"}, "not a positive Go duration"},
		{map[string]string{SoakWindowEnv: "-5m"}, "not a positive Go duration"},
		{map[string]string{SoakWindowEnv: "0s"}, "not a positive Go duration"},
		{map[string]string{SoakLeaseEnv: "40s"}, "not a positive number of seconds"},
		{map[string]string{SoakLeaseEnv: "0"}, "not a positive number of seconds"},
		{map[string]string{SoakWindowEnv: "79s"}, "under two 40s leases"},
		{map[string]string{SoakWindowEnv: "10m", SoakLeaseEnv: "301"}, "under two 301s leases"},
	} {
		if _, err := SoakFromEnv(soakEnv(c.env)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: got %v, want an error containing %q", c.env, err, c.want)
		}
	}
	if _, err := SoakFromEnv(soakEnv(map[string]string{SoakWindowEnv: "80s"})); err != nil {
		t.Errorf("exactly two leases: %v", err)
	}
}
