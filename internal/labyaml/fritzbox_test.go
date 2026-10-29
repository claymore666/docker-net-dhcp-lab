package labyaml

import (
	"encoding/json"
	"strings"
	"testing"
)

// goodMin plus the ula_prefix a cell with an IPv6 segment needs.
var goodMinULA = strings.Replace(goodMin, "cells:", "ula_prefix: \"fd42:200::/48\"\ncells:", 1)

// The fritzbox cell as lab #13 PR 1 ships it, beside the minimal cell.
var withFritzbox = goodMinULA + `
  - name: fritzbox
    segment:
      bridge: lab-br-fritzbox
      subnet: 10.200.17.0/24
      subnet6: "fd42:200:0:1100::/64"
      uplink: lab1
    source:
      type: fritzbox
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.171/24
      seg_address: 10.200.17.1/24
      pool_start: 10.200.17.100
      pool_end: 10.200.17.200
      seg_address6: "fd42:200:0:1100::1/64"
      pool6_start: "fd42:200:0:1100::100"
      pool6_end: "fd42:200:0:1100::1ff"
      temp6_pool: "fd42:200:0:1100::200/120"
      device:
        address: 10.200.17.1/24
        probe_address: 10.200.17.2/24
        tr064_user: lab
        password_env: LAB_FRITZBOX_PASSWORD
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.170/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.5.0
`

func TestAcceptsFritzboxCell(t *testing.T) {
	c, err := Load(write(t, withFritzbox))
	if err != nil {
		t.Fatalf("valid fritzbox cell rejected: %v", err)
	}
	cell, err := c.CellByName("fritzbox")
	if err != nil {
		t.Fatal(err)
	}
	if cell.Source.Device == nil || cell.Source.Device.PasswordEnv != "LAB_FRITZBOX_PASSWORD" || cell.Segment.Uplink != "lab1" {
		t.Fatalf("device or uplink lost in parsing: %+v %q", cell.Source.Device, cell.Segment.Uplink)
	}
}

func TestFritzboxRefusals(t *testing.T) {
	const deviceBlock = `      device:
        address: 10.200.17.1/24
        probe_address: 10.200.17.2/24
        tr064_user: lab
        password_env: LAB_FRITZBOX_PASSWORD
`
	cases := []struct{ name, from, to, want string }{
		{"missing device", deviceBlock, "", "source.device is required"},
		{"device outside the segment", "address: 10.200.17.1/24\n        probe", "address: 10.200.18.1/24\n        probe", "source.device.address"},
		{"device is not the seg_address", "      device:\n        address: 10.200.17.1/24", "      device:\n        address: 10.200.17.3/24", "differs from source.seg_address"},
		{"device is the network address", "      device:\n        address: 10.200.17.1/24", "      device:\n        address: 10.200.17.0/24", "source.device.address"},
		{"probe is the box", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.1/24", "is the box's own address"},
		{"probe is the broadcast address", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.255/24", "source.device.probe_address"},
		{"probe has another prefix length", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.2/25", "source.device.probe_address"},
		{"probe inside the pool", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.150/24", "source pool covers 10.200.17.150"},
		{"probe on the first pool address", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.100/24", "source pool covers 10.200.17.100"},
		{"probe on the last pool address", "probe_address: 10.200.17.2/24", "probe_address: 10.200.17.200/24", "source pool covers 10.200.17.200"},
		{"seg_address with another prefix length", "seg_address: 10.200.17.1/24", "seg_address: 10.200.17.1/25", "differs from source.seg_address"},
		{"pool starting below the probe", "pool_start: 10.200.17.100", "pool_start: 10.200.17.1", "overlaps the source's own seg_address"},
		{"no user", "tr064_user: lab\n", "tr064_user: \"\"\n", "tr064_user is required"},
		{"no password_env", "password_env: LAB_FRITZBOX_PASSWORD", "password_env: \"\"", "password_env must name an environment variable"},
		{"literal password", "password_env: LAB_FRITZBOX_PASSWORD", "password_env: hunter2", "never the password itself"},
		{"password with a symbol", "password_env: LAB_FRITZBOX_PASSWORD", "password_env: \"S3cret!pass\"", "never the password itself"},
		{"no uplink", "      uplink: lab1\n", "", "segment.uplink is required for source.type fritzbox"},
		{"no subnet6", "      subnet6: \"fd42:200:0:1100::/64\"\n", "", "set on a cell with no segment.subnet6"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := strings.Replace(withFritzbox, tc.from, tc.to, 1)
			if bad == withFritzbox {
				t.Fatalf("test bug: %q not found", tc.from)
			}
			_, err := Load(write(t, bad))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestDeviceOnAnotherSourceTypeIsRefused(t *testing.T) {
	bad := strings.Replace(strings.Replace(withFritzbox, "type: fritzbox", "type: kea", 1), "      uplink: lab1\n", "", 1)
	if _, err := Load(write(t, bad)); err == nil || !strings.Contains(err.Error(), "source.device is only for source.type fritzbox") {
		t.Fatalf("device on a kea cell: %v", err)
	}
}

func TestUplinkOnAnotherSourceTypeIsRefused(t *testing.T) {
	// device dropped so only the uplink rule can speak
	bad := strings.Replace(withFritzbox, "type: fritzbox", "type: kea", 1)
	i := strings.Index(bad, "      device:")
	j := strings.Index(bad, "    docker_host:\n      base_image: debian-13-generic-amd64\n      mgmt_address: 10.200.255.170")
	bad = bad[:i] + bad[j:]
	if _, err := Load(write(t, bad)); err == nil || !strings.Contains(err.Error(), "segment.uplink is only for source.type fritzbox") {
		t.Fatalf("uplink on a kea cell: %v", err)
	}
	noSource := goodMin + `
  - name: bare
    segment:
      bridge: lab-br-bare
      subnet: 10.200.20.0/24
      uplink: lab0
    docker_host:
      base_image: debian-13-generic-amd64
      mgmt_address: 10.200.255.11/24
      plugin_tag: ghcr.io/claymore666/docker-net-dhcp:v2.5.0
`
	if _, err := Load(write(t, noSource)); err == nil || !strings.Contains(err.Error(), "segment.uplink is only for source.type fritzbox") {
		t.Fatalf("uplink on a cell with no source: %v", err)
	}
}

func TestUplinkAllowList(t *testing.T) {
	for _, ok := range []string{"lab0", "lab1", "lab0.1", "lab0.100", "lab0.4094"} {
		bad := strings.Replace(withFritzbox, "uplink: lab1", "uplink: "+ok, 1)
		if _, err := Load(write(t, bad)); err != nil {
			t.Errorf("uplink %q refused: %v", ok, err)
		}
	}
	for _, no := range []string{"eth0", "eth1", "lab2", "lab0.0", "lab0.4095", "lab0.x", "lab0.01", "lab1.5", "LAB0", "lab0.", "br0", "lab0 "} {
		bad := strings.Replace(withFritzbox, "uplink: lab1", "uplink: \""+no+"\"", 1)
		_, err := Load(write(t, bad))
		if err == nil || !strings.Contains(err.Error(), "is not one of lab0, lab0.N (N 1-4094) or lab1") {
			t.Errorf("uplink %q: want an allow-list refusal, got %v", no, err)
		}
	}
}

func TestUplinkReusedByTwoCellsIsRefused(t *testing.T) {
	second := strings.Replace(withFritzbox[strings.Index(withFritzbox, "  - name: fritzbox"):], "fritzbox", "fritzbox2", 1)
	r := strings.NewReplacer("lab-br-fritzbox", "lab-br-fb2", "10.200.17.", "10.200.18.", "fd42:200:0:1100::", "fd42:200:0:1200::",
		"10.200.255.171", "10.200.255.181", "10.200.255.170", "10.200.255.180")
	_, err := Load(write(t, withFritzbox+r.Replace(second)))
	if err == nil || !strings.Contains(err.Error(), "already enslaved by cell fritzbox") {
		t.Fatalf("two cells on lab1: %v", err)
	}
}

func TestRelayServerSegmentRefusesUplink(t *testing.T) {
	bad := strings.Replace(withRelay, "        bridge: lab-br-kea-rsv\n", "        bridge: lab-br-kea-rsv\n        uplink: lab0\n", 1)
	if bad == withRelay {
		t.Fatal("test bug: server_segment bridge line not found")
	}
	_, err := Load(write(t, bad))
	if err == nil || !strings.Contains(err.Error(), "server_segment.uplink is not supported") {
		t.Fatalf("uplink on a relay server segment: %v", err)
	}
}

// A pool that spans the source's own address strictly inside it was
// accepted for every type; only the two ends were compared (lab #13).
func TestRejectsPoolCoveringSegAddress(t *testing.T) {
	for name, body := range map[string]string{
		"kea":      strings.Replace(withSource, "pool_start: 10.200.1.100", "pool_start: 10.200.1.1", 1),
		"fritzbox": strings.Replace(withFritzbox, "pool_start: 10.200.17.100", "pool_start: 10.200.17.0", 1),
		"kea, seg_address on the last pool address":      strings.Replace(strings.Replace(withSource, "pool_start: 10.200.1.100", "pool_start: 10.200.1.1", 1), "pool_end: 10.200.1.200", "pool_end: 10.200.1.2", 1),
		"fritzbox, seg_address on the last pool address": strings.Replace(strings.Replace(withFritzbox, "pool_start: 10.200.17.100", "pool_start: 10.200.17.0", 1), "pool_end: 10.200.17.200", "pool_end: 10.200.17.1", 1),
	} {
		_, err := Load(write(t, body))
		if err == nil || !strings.Contains(err.Error(), "overlaps the source's own seg_address") {
			t.Errorf("%s: pool spanning seg_address: %v", name, err)
		}
	}
}

func TestFritzboxServesV6(t *testing.T) {
	if !SourceServesV6("fritzbox") {
		t.Fatal("SourceServesV6(fritzbox) = false")
	}
}

// The new keys are omitted for every cell without them, so every other
// cell's resolve output is the bytes it was (lab #13).
func TestExistingCellsMarshalWithoutNewKeys(t *testing.T) {
	c, err := Load(write(t, withSource))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(c.Cells[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"uplink", "device"} {
		if strings.Contains(string(b), k) {
			t.Errorf("kea cell JSON carries %q: %s", k, b)
		}
	}
}

// up-cell.sh and the probe seed read these paths with jq (lab #13 PRs 2, 4).
func TestFritzboxResolveJSONPaths(t *testing.T) {
	c, err := Load(write(t, withFritzbox))
	if err != nil {
		t.Fatal(err)
	}
	cell, _ := c.CellByName("fritzbox")
	b, _ := json.Marshal(cell)
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	seg, _ := raw["segment"].(map[string]any)
	src, _ := raw["source"].(map[string]any)
	if seg["uplink"] != "lab1" {
		t.Errorf("segment.uplink = %v", seg["uplink"])
	}
	dev, _ := src["device"].(map[string]any)
	want := map[string]string{"address": "10.200.17.1/24", "probe_address": "10.200.17.2/24", "tr064_user": "lab", "password_env": "LAB_FRITZBOX_PASSWORD"}
	for k, v := range want {
		if dev[k] != v {
			t.Errorf("source.device.%s = %v, want %s", k, dev[k], v)
		}
	}
}

// The shipped cell, pinned to the design: subnet, box at .1, probe at .2,
// pool .100-.200 (the group F user-class pool owns .203-.210), a /64 of
// the ULA /48. 10.200.16.0/24 is the Windows cell's alone (lab #13, #14).
func TestRealLabYAMLFritzboxCell(t *testing.T) {
	c, err := Load("../../lab.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cell, err := c.CellByName("fritzbox")
	if err != nil {
		t.Fatal(err)
	}
	s, d := cell.Source, cell.Source.Device
	got := []string{cell.Segment.Subnet, cell.Segment.Subnet6, cell.Segment.Uplink, s.Type, s.SegAddress, s.PoolStart, s.PoolEnd, d.Address, d.ProbeAddress}
	want := []string{"10.200.17.0/24", "fd42:200:0:1100::/64", "lab1", "fritzbox", "10.200.17.1/24", "10.200.17.100", "10.200.17.200", "10.200.17.1/24", "10.200.17.2/24"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("fritzbox cell\n got %v\nwant %v", got, want)
	}
	for _, o := range c.Cells {
		if o.Segment.Subnet == "10.200.16.0/24" && o.Name != "windows" {
			t.Errorf("cell %s sits on 10.200.16.0/24, the windows cell's slot", o.Name)
		}
	}
}
