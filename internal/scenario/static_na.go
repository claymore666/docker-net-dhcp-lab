package scenario

import (
	"github.com/claymore666/docker-net-dhcp-lab/internal/sourceadapter"
)

// ipamStaticNA lists the scenarios whose first act is the ipam shape
// check (bIPAMNA or ipamNA), mapped to the network that check names in
// its reason. On an ipam shape the shape alone decides their result, so
// StaticNA can write that N/A before the per-scenario wrapper does any
// work (#79). The set is read off the scenario bodies by
// TestStaticNATableMatchesTheScenarios, which fails when a scenario is
// added to or dropped from the ipam check without a row here.
var ipamStaticNA = map[string]string{
	NameB2: optionNetworkWhat, NameB5: optionNetworkWhat, NameB6: optionNetworkWhat,
	NameB7: optionNetworkWhat,
	NameC1: optionNetworkWhat, NameC6: optionNetworkWhat, NameC6b: optionNetworkWhat,
	NameC7: optionNetworkWhat, NameC8: optionNetworkWhat, NameC9: c9NetworkWhat,
	NameC11: optionNetworkWhat, NameC12: optionNetworkWhat,
	NameD1c: optionNetworkWhat, NameD2b: optionNetworkWhat,
	NameD3a: optionNetworkWhat, NameD3b: optionNetworkWhat, NameD3c: optionNetworkWhat,
	NameD3d: optionNetworkWhat, NameD4: optionNetworkWhat, NameD4m: optionNetworkWhat,
	NameD4b: optionNetworkWhat,
	NameF1:  optionNetworkWhat, NameF2b: optionNetworkWhat, NameF3: optionNetworkWhat,
	NameF4: optionNetworkWhat, NameF5: optionNetworkWhat, NameF6: optionNetworkWhat,
	NameF7: optionNetworkWhat, NameF8: optionNetworkWhat,
}

// shapeStaticNA lists the scenarios whose first act is a shape N/A other
// than the ipam one, each with the function the scenario body calls. The
// set is read off the scenario bodies by TestShapeStaticNATableMatchesTheScenarios.
var shapeStaticNA = map[string]func(Env) (Verdict, bool){
	NameC6: c6IpvlanNA,
}

// StaticNA returns the verdict RunOne would produce for s, when the shape
// alone decides it and nothing RunOne checks first can change it: the
// source declares what s needs (else the capability N/A keeps its own
// reason), the source type has no shape reason for s, and the shape is an
// ipam one. The verdict is built by the same ipamNA the scenario body
// calls and carries the host as RunOne stamps it; the second result is
// false for every other scenario, whose path stays as it was. e needs
// Cell, Shape, GitSHA, Source and HostInfo.
func StaticNA(s Scenario, e Env) (Verdict, bool) {
	network, ipam := ipamStaticNA[s.Name]
	shapeNA, shape := shapeStaticNA[s.Name]
	if !ipam && !shape {
		return Verdict{}, false
	}
	if ok, _ := Applicable(s, e.Source); !ok {
		return Verdict{}, false
	}
	if sr, ok := e.Source.(sourceadapter.ShapeNAReasoner); ok && sr.NAShapeReason(string(e.Shape), s.Name) != "" {
		return Verdict{}, false
	}
	var v Verdict
	var ok bool
	if ipam {
		v, ok = ipamNA(s.Name, e, network)
	}
	if !ok && shape {
		v, ok = shapeNA(e)
	}
	if !ok {
		return Verdict{}, false
	}
	v.Host = e.HostInfo
	return v, true
}
