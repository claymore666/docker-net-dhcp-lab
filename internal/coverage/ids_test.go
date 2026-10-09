package coverage

import (
	"errors"
	"testing"
)

func TestParseID_RoundTripsEveryKind(t *testing.T) {
	for _, s := range []string{
		"ipv6_mode=dhcp@bridge",
		"LOG_LEVEL=debug",
		"ipv6_mode=!bogus",
		"vlan@!bridge",
		"alias:ipv6=true~ipv6_mode=dhcp@macvlan",
		"alias:ipv6=true~ipv6=true+ipv6_mode=dhcp@ipvlan",
		"alias:lease_timeout=0~lease_timeout=unset",
		"pair:ipv6_mode=dhcp+ipv6_pd=64@bridge",
		"env:skip_routes=true@bridge#E3",
	} {
		id, err := ParseID(s)
		if err != nil {
			t.Errorf("ParseID(%q): %v", s, err)
			continue
		}
		if got := id.String(); got != s {
			t.Errorf("ParseID(%q).String() = %q", s, got)
		}
	}
}

func TestParseID_RejectsMalformedIDs(t *testing.T) {
	for _, s := range []string{
		"", "ipv6_mode", "ipv6_mode=", "=dhcp@bridge", "alias:a=b", "pair:a=1+b=2",
		"pair:a=1@bridge", "env:a=1@bridge", "env:a=1#E1", "env:a=1@bridge#E9",
		"ipv6_mode=!bogus@bridge", "a b=1", "@!bridge",
	} {
		if _, err := ParseID(s); err == nil {
			t.Errorf("ParseID(%q) succeeded", s)
		}
	}
}

func TestParseID_GlobOnAnOptionNameIsErrGlob(t *testing.T) {
	for _, s := range []string{"*=dhcp@bridge", "ipv6*=dhcp@bridge", "*@!bridge", "pair:*=1+b=2@bridge", "alias:a=1~*=2"} {
		_, err := ParseID(s)
		var g ErrGlob
		if !errors.As(err, &g) {
			t.Errorf("ParseID(%q) = %v, want ErrGlob", s, err)
		}
	}
}

func TestID_MatchesHonoursValueModeAndProfileGlobs(t *testing.T) {
	cases := []struct {
		pattern, id string
		want        bool
	}{
		{"ipv6_mode=dhcp@bridge", "ipv6_mode=dhcp@bridge", true},
		{"ipv6_mode=dhcp@bridge", "ipv6_mode=dhcp@macvlan", false},
		{"ipv6_mode=*@bridge", "ipv6_mode=slaac@bridge", true},
		{"ipv6_mode=*@*", "ipv6_mode=slaac@ipvlan", true},
		{"ipv6_mode=*@bridge", "ipv6_pd=64@bridge", false},
		{"ipv6_mode=*@bridge", "ipv6_mode=!bogus", false},
		{"ipv6_mode=!*", "ipv6_mode=!bogus", true},
		{"ipv6_mode=!*", "ipv6_mode=dhcp@bridge", false},
		{"vlan@!bridge", "vlan@!bridge", true},
		{"vlan@!bridge", "vlan@!ipvlan", false},
		{"pair:ipv6_mode=*+ipv6_pd=64@*", "pair:ipv6_mode=dhcp+ipv6_pd=64@bridge", true},
		{"pair:ipv6_mode=*+ipv6_pd=64@*", "pair:ipv6_mode=dhcp+ipv6_pd=1@bridge", false},
		{"env:ipv6_mode=dhcp@bridge#*", "env:ipv6_mode=dhcp@bridge#E4", true},
		{"env:ipv6_mode=dhcp@bridge#E1", "env:ipv6_mode=dhcp@bridge#E4", false},
		{"ipv6_mode=dhcp@bridge", "env:ipv6_mode=dhcp@bridge#E1", false},
	}
	for _, c := range cases {
		p, err := ParseID(c.pattern)
		if err != nil {
			t.Fatalf("pattern %q: %v", c.pattern, err)
		}
		v, err := ParseID(c.id)
		if err != nil {
			t.Fatalf("id %q: %v", c.id, err)
		}
		if got := p.Matches(v); got != c.want {
			t.Errorf("%q.Matches(%q) = %v, want %v", c.pattern, c.id, got, c.want)
		}
	}
}
