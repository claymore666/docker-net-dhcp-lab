#!/usr/bin/env python3
"""Wire tool for the home Fritz.Box run (lab #13): reads the run's pcap, sends the cleanup frames."""
import argparse
import json
import os
import random
import re
import select
import socket
import struct
import sys
import time

MT = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}
MAGIC = b"\x63\x82\x53\x63"
BCAST = "ff:ff:ff:ff:ff:ff"
E2_NAMES = ("leases_obtained", "leases_renewed", "lease_changed", "renewals_unanswered", "dhcp_timeouts",
            "naks_received", "releases_sent")


def mac_s(b):
    return ":".join("%02x" % x for x in b)


def mac_b(s):
    return bytes.fromhex(s.replace(":", ""))


def read_pcap(path):
    """Yield (ts, frame) from a classic pcap with Ethernet link type; a truncated tail is ignored."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        magic = struct.unpack("<I", hdr[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end = "<"
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            end = ">"
        else:
            raise SystemExit("%s: not a pcap file" % path)
        nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
        if struct.unpack(end + "I", hdr[20:24])[0] != 1:
            raise SystemExit("%s: link type is not Ethernet" % path)
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            sec, frac, incl, _ = struct.unpack(end + "IIII", ph)
            data = f.read(incl)
            if len(data) < incl:
                return
            yield sec + frac / (1e9 if nano else 1e6), data


def parse_dhcp(frame):
    """Return a dict for a DHCPv4 frame over Ethernet/IPv4/UDP 67-68, else None."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 8 or ip[9] != 17:
        return None
    sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
    if {sport, dport} - {67, 68}:
        return None
    b = ip[ihl + 8:]
    if len(b) < 240 or b[236:240] != MAGIC:
        return None
    d = {"esrc": mac_s(frame[6:12]), "edst": mac_s(frame[0:6]), "op": b[0],
         "xid": struct.unpack("!I", b[4:8])[0], "ciaddr": socket.inet_ntoa(b[12:16]),
         "yiaddr": socket.inet_ntoa(b[16:20]), "chaddr": mac_s(b[28:34]), "opts": {}}
    i = 240
    while i < len(b):
        code = b[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        d["opts"][code] = b[i + 2:i + 2 + ln]
        i += 2 + ln
    o = d["opts"]
    d["type"] = MT.get(o.get(53, b"\0")[0], "?")
    d["server"] = socket.inet_ntoa(o[54]) if len(o.get(54, b"")) == 4 else ""
    d["reqip"] = socket.inet_ntoa(o[50]) if len(o.get(50, b"")) == 4 else ""
    d["cid"] = o.get(61, b"").hex()
    d["rapid"] = 80 in o
    d["fqdn"] = 81 in o
    d["msg"] = o.get(56, b"").decode(errors="replace")
    d["hostname"] = o.get(12, b"").decode(errors="replace")
    return d


def dhcp_msgs(paths):
    """DHCP messages of one or more captures (a cleanup after a power cut adds a second file), in time order."""
    out = []
    for path in [paths] if isinstance(paths, str) else paths:
        for ts, fr in read_pcap(path):
            d = parse_dhcp(fr)
            if d:
                d["t"] = ts
                out.append(d)
    return sorted(out, key=lambda m: m["t"])


def acked(msgs, macs, server):
    """Every address the server ever ACKed to one of macs, with its last holder: what the cleanup verifies."""
    out = {}
    for m in msgs:
        if m["op"] == 2 and m["type"] == "ACK" and m["server"] == server and m["chaddr"] in macs:
            out[m["yiaddr"]] = m["chaddr"]
    return out


def ledger(msgs, macs, server):
    """Held leases: the server's last ACK per (chaddr, yiaddr) with no later RELEASE of that address by that chaddr."""
    held, cid = {}, {}
    for m in msgs:
        if m["chaddr"] not in macs:
            continue
        if m["op"] == 1 and m["cid"]:
            cid[m["chaddr"]] = m["cid"]
        if m["op"] == 2 and m["type"] == "ACK" and m["server"] == server:
            held[(m["chaddr"], m["yiaddr"])] = cid.get(m["chaddr"], "")
        if m["op"] == 1 and m["type"] == "RELEASE":
            held.pop((m["chaddr"], m["ciaddr"]), None)
    return held


def guard(msgs, allowed, host_mac):
    """Problems on the outbound capture: a client frame from a MAC outside the budget that is ours (hostname lab-fb-*,
    or our 02:fd:4b:00:13 prefix), or a DECLINE from ours. Other hosts' and containers' frames are not ours to judge
    or release: returned apart, as foreign."""
    probs, foreign = [], []
    for m in msgs:
        if m["op"] != 1:
            continue
        for who in (m["esrc"], m["chaddr"]):
            if who == host_mac or who in allowed:
                continue
            if m["hostname"].startswith("lab-fb") or who.startswith("02:fd:4b:00:13"):
                probs.append("client frame from %s outside the MAC budget (%s)" % (who, m["type"]))
            else:
                foreign.append("foreign client frame from %s (%s)" % (who, m["type"]))
        if m["type"] == "DECLINE" and m["chaddr"] in allowed:
            probs.append("DECLINE from %s for %s" % (m["chaddr"], m["reqip"]))
    return sorted(set(probs)), sorted(set(foreign))


def summarize(msgs, mac, since):
    rows = []
    for m in msgs:
        if m["t"] < since or m["chaddr"] != mac:
            continue
        rows.append({"t": round(m["t"], 3), "dir": "client" if m["op"] == 1 else "server", "type": m["type"],
                     "xid": "%08x" % m["xid"], "ciaddr": m["ciaddr"], "yiaddr": m["yiaddr"], "reqip": m["reqip"],
                     "server": m["server"], "rapid": m["rapid"], "fqdn": m["fqdn"], "cid": m["cid"], "msg": m["msg"],
                     "hostname": m["hostname"]})
    return rows


def exchanges(msgs, mac, since, server):
    """One row per XID: how the client started it (RFC 2131 4.3.2 kinds) and what the server answered."""
    by, order = {}, []
    for m in msgs:
        if m["t"] < since or m["chaddr"] != mac:
            continue
        x = by.get(m["xid"])
        if x is None:
            if m["op"] != 1:
                continue
            if m["type"] == "DISCOVER":
                start = "discover"
            elif m["type"] == "REQUEST" and m["ciaddr"] != "0.0.0.0" and m["edst"] != BCAST:
                start = "renew"
            elif m["type"] == "REQUEST" and m["ciaddr"] != "0.0.0.0":
                start = "rebind"
            elif m["type"] == "REQUEST" and not m["server"]:
                start = "init-reboot"
            elif m["type"] == "REQUEST":
                start = "select"
            else:
                start = m["type"].lower()
            x = by[m["xid"]] = {"start": start, "outcome": "none", "yiaddr": "-", "rapid": m["rapid"],
                                "offers": 0, "msg": ""}
            order.append(m["xid"])
        if m["op"] == 2 and m["server"] == server:
            if m["type"] == "OFFER":
                x["offers"] += 1
            elif m["type"] in ("ACK", "NAK") and x["outcome"] == "none":
                x["outcome"], x["yiaddr"], x["msg"] = m["type"], m["yiaddr"], m["msg"]
    return [by[k] for k in order]


def build_frame(src_mac, dst_mac, src_ip, dst_ip, chaddr, xid, ciaddr, opts):
    bootp = struct.pack("!BBBBIHH", 1, 1, 6, 0, xid, 0, 0x8000 if dst_ip == "255.255.255.255" else 0)
    bootp += socket.inet_aton(ciaddr) + b"\0" * 12 + mac_b(chaddr) + b"\0" * 10 + b"\0" * 192 + MAGIC
    for code, val in opts:
        bootp += bytes([code, len(val)]) + val
    bootp += b"\xff"
    udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    s = sum(struct.unpack("!10H", iph))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    iph = iph[:10] + struct.pack("!H", ~s & 0xFFFF) + iph[12:]
    return mac_b(dst_mac) + mac_b(src_mac) + b"\x08\x00" + iph + udp


def raw_socket(iface, proto):
    """AF_PACKET socket with a promiscuous membership: the reply to a MAC with no link here is unicast to it."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(proto))
    s.bind((iface, 0))
    mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), 1, 0, b"")
    s.setsockopt(263, 1, mreq)  # SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC; dropped on close
    return s


def send_release(a):
    opts = [(53, b"\x07"), (54, socket.inet_aton(a.server))]
    if a.cid:
        opts.append((61, bytes.fromhex(a.cid)))
    fr = build_frame(a.mac, a.smac, a.ip, a.server, a.mac, random.randint(1, 0xFFFFFFFF), a.ip, opts)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    s.send(fr)
    print(json.dumps({"release": a.ip, "mac": a.mac, "cid": a.cid}))


def offer_check(a):
    """One DISCOVER asking for --ip from --mac; exit 0 only if the server offers exactly that address."""
    xid = random.randint(1, 0xFFFFFFFF)
    fr = build_frame(a.mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", a.mac, xid, "0.0.0.0",
                     [(53, b"\x01"), (50, socket.inet_aton(a.ip)), (55, bytes([1, 3, 6, 51, 54]))])
    s = raw_socket(a.iface, 0x0800)
    s.send(fr)
    end, got = time.time() + a.wait, None
    while time.time() < end and got is None:
        r, _, _ = select.select([s], [], [], max(0.0, end - time.time()))
        if not r:
            break
        d = parse_dhcp(s.recv(4096))
        if d and d["op"] == 2 and d["xid"] == xid:
            got = d
    res = {"asked": a.ip, "mac": a.mac, "type": got["type"] if got else None,
           "yiaddr": got["yiaddr"] if got else None, "server": got["server"] if got else None}
    print(json.dumps(res))
    return 0 if got and got["type"] == "OFFER" and got["yiaddr"] == a.ip else 1


def arp_probe(a):
    """RFC 5227 probe (sender 0.0.0.0) for --target from --mac; exit 0 if a reply arrives."""
    m = mac_b(a.mac)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + m + b"\0" * 4 + b"\0" * 6 + socket.inet_aton(a.target)
    s = raw_socket(a.iface, 0x0806)
    replies = []
    for _ in range(a.count):
        s.send(b"\xff" * 6 + m + b"\x08\x06" + arp)
        end = time.time() + 1.0
        while time.time() < end:
            r, _, _ = select.select([s], [], [], max(0.0, end - time.time()))
            if not r:
                break
            p = s.recv(128)
            if len(p) >= 42 and p[0:6] == m and p[20:22] == b"\x00\x02" and p[28:32] == socket.inet_aton(a.target):
                replies.append(mac_s(p[22:28]))
    print(json.dumps({"target": a.target, "replies": len(replies), "count": a.count}))
    return 0 if replies else 1


METRIC_RE = re.compile(r'^net_dhcp_([a-z0-9_]+)_total\{family="(ipv4|ipv6)"\} ([0-9]+)$')


def parse_metrics(text):
    out = {}
    for line in text.splitlines():
        m = METRIC_RE.match(line.strip())
        if m and m.group(1) in E2_NAMES:
            out[m.group(1) + ("_v4" if m.group(2) == "ipv4" else "_v6")] = int(m.group(3))
    return out


def wire_classes(xs):
    """Exchange start kinds as the lab's group E judge names them (lab #123: an INIT-REBOOT resume is in no count)."""
    cls = {"discover": "bound", "renew": "renew", "init-reboot": "resume"}
    return [(cls.get(x["start"], "other"), x) for x in xs if x["outcome"] == "ACK"]


def client_count(msgs, mac, since, kind):
    return sum(1 for m in msgs if m["t"] >= since and m["op"] == 1 and m["chaddr"] == mac and m["type"] == kind)


def judge_e1(msgs, mac, since, server, ledger_lines, network, released):
    """Ledger vs wire: one bound per DISCOVER-started ACK, one renew per unicast renewal, same address order; the one
    RELEASE on the wire is the one releases_sent_v4 counted (lab groupe_judge.go judgeE1)."""
    got, fails = [], []
    for ln in ledger_lines:
        if not ln.strip():
            continue
        e = json.loads(ln)
        net = str(e.get("network", ""))
        if not net or not network or not (net.startswith(network) or network.startswith(net)):
            continue
        k = e.get("kind", "")
        if k.startswith("release"):
            fails.append("ledger has a release-like entry %r" % k)
        elif k in ("bound", "renew"):
            got.append((k, e.get("ip", "")))
        elif k not in ("stopped", "stop_failed"):
            return "BLOCKED", "ledger entry of unknown kind %r" % k
    if not got and not fails:
        return "BLOCKED", "the audit ledger has no entry for this network"
    want = []
    for c, x in wire_classes(exchanges(msgs, mac, since, server)):
        if c in ("bound", "renew"):
            want.append((c, x["yiaddr"]))
        elif c == "other":
            fails.append("an ACKed exchange started by %s is in no ledger kind" % x["start"])
    if got != want:
        fails.append("ledger %s differs from the wire %s" % (got, want))
    rel = client_count(msgs, mac, since, "RELEASE")
    dec = client_count(msgs, mac, since, "DECLINE")
    if dec:
        fails.append("the wire shows %d DECLINE" % dec)
    if rel != 1:
        fails.append("the wire shows %d RELEASE, want exactly 1 after release_lease=on_stop" % rel)
    if rel != released:
        fails.append("the wire shows %d RELEASE but releases_sent_v4 moved by %d" % (rel, released))
    if fails:
        return "FAIL", "; ".join(fails)
    return "PASS", "ledger %s matches the box's ACKs on the wire in address order; 1 RELEASE on the wire equals releases_sent_v4; no DECLINE" % got


def judge_e2(msgs, mac, since, server, before, after, health, address):
    """Counter deltas vs the wire, flat failure counters, /metrics and /Plugin.Health agree (lab judgeE2)."""
    fails, delta = [], {}
    for n in E2_NAMES:
        k = n + "_v4"
        if k not in before or k not in after:
            return "BLOCKED", "the %s series is missing from a /metrics scrape" % k
        if after[k] < before[k]:
            return "BLOCKED", "%s went backwards: the plugin restarted inside the window" % k
        delta[n] = after[k] - before[k]
    cl = wire_classes(exchanges(msgs, mac, since, server))
    naks = sum(1 for m in msgs if m["t"] >= since and m["op"] == 2 and m["chaddr"] == mac and m["type"] == "NAK")
    want = {"leases_obtained": sum(1 for c, _ in cl if c == "bound"), "leases_renewed": sum(1 for c, _ in cl if c == "renew"),
            "releases_sent": client_count(msgs, mac, since, "RELEASE"), "naks_received": naks}
    for n, w in want.items():
        if delta[n] != w:
            fails.append("%s moved by %d, the wire says %d" % (n, delta[n], w))
    if naks:
        fails.append("the capture shows a NAK for this client")
    for n in ("dhcp_timeouts", "renewals_unanswered", "lease_changed"):
        if delta[n]:
            fails.append("%s moved by %d, want 0" % (n, delta[n]))
    for c, x in cl:
        if c == "other":
            fails.append("an ACKed exchange started by %s is in no counter" % x["start"])
        if x["yiaddr"] != address:
            fails.append("an ACK granted %s but the container holds %s" % (x["yiaddr"], address))
    for n in E2_NAMES:
        h, h4, h6 = health.get(n), health.get(n + "_v4"), health.get(n + "_v6")
        m4, m6 = after.get(n + "_v4", 0), after.get(n + "_v6", 0)
        if h is None or h4 is None or h6 is None:
            fails.append("/Plugin.Health lacks %s" % n)
        elif h4 != m4 or h6 != m6 or h != m4 + m6:
            fails.append("%s: /Plugin.Health v4=%d v6=%d sum=%d, /metrics v4=%d v6=%d" % (n, h4, h6, h, m4, m6))
    if fails:
        return "FAIL", "; ".join(fails)
    return "PASS", "obtained +%d, renewed +%d, released +%d match the box's frames on the wire; timeouts, unanswered, lease_changed and NAKs flat; /metrics and /Plugin.Health agree" % (
        delta["leases_obtained"], delta["leases_renewed"], delta["releases_sent"])


def redact(text, prefix, macs):
    """Rewrite the live /24 prefix to 192.0.2. and each live MAC to a placeholder (lab rule: no home detail)."""
    if prefix:
        text = re.sub(r"(?<![0-9.])" + re.escape(prefix) + r"(?=[0-9]{1,3}(?![0-9]))", "192.0.2.", text)
    for mac, name in macs:
        if mac:
            text = re.sub(re.escape(mac), name, text, flags=re.IGNORECASE)
    return text


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    for name in ("ledger", "acked"):
        p = sp.add_parser(name)
        p.add_argument("pcap", nargs="+")
        p.add_argument("--macs", required=True)
        p.add_argument("--server", required=True)
    p = sp.add_parser("guard")
    p.add_argument("pcap")
    p.add_argument("--macs", required=True)
    p.add_argument("--host-mac", required=True)
    p = sp.add_parser("events")
    p.add_argument("pcap")
    p.add_argument("--mac", required=True)
    p.add_argument("--since", type=float, default=0.0)
    p = sp.add_parser("exchanges")
    p.add_argument("pcap")
    p.add_argument("--mac", required=True)
    p.add_argument("--server", required=True)
    p.add_argument("--since", type=float, default=0.0)
    p = sp.add_parser("release")
    for k in ("iface", "mac", "ip", "server", "smac"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--cid", default="")
    p = sp.add_parser("offer")
    for k in ("iface", "mac", "ip"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--wait", type=float, default=6.0)
    p = sp.add_parser("arp-probe")
    for k in ("iface", "mac", "target"):
        p.add_argument("--" + k, required=True)
    p.add_argument("--count", type=int, default=2)
    sp.add_parser("redact")
    for name in ("e1", "e2"):
        p = sp.add_parser(name)
        for k in ("pcap", "mac", "server", "before", "after"):
            p.add_argument("--" + k, required=True)
        p.add_argument("--since", type=float, default=0.0)
        p.add_argument("--ledger", default="")
        p.add_argument("--network", default="")
        p.add_argument("--health", default="")
        p.add_argument("--address", default="")
    a = ap.parse_args()
    if a.cmd == "ledger":
        for (mac, ip), cid in sorted(ledger(dhcp_msgs(a.pcap), set(a.macs.split(",")), a.server).items()):
            print(mac, ip, cid or "-")
    elif a.cmd == "acked":
        for ip, mac in sorted(acked(dhcp_msgs(a.pcap), set(a.macs.split(",")), a.server).items()):
            print(ip, mac)
    elif a.cmd == "guard":
        probs, foreign = guard(dhcp_msgs(a.pcap), set(a.macs.split(",")), a.host_mac.lower())
        print("\n".join(probs))
        if foreign:
            print("\n".join(foreign), file=sys.stderr)
        return 1 if probs else 0
    elif a.cmd == "events":
        for r in summarize(dhcp_msgs(a.pcap), a.mac.lower(), a.since):
            print(json.dumps(r, sort_keys=True))
    elif a.cmd == "exchanges":
        for x in exchanges(dhcp_msgs(a.pcap), a.mac.lower(), a.since, a.server):
            print(x["start"], x["outcome"], x["yiaddr"], "rapid" if x["rapid"] else "-", "offers=%d" % x["offers"],
                  x["msg"].replace(" ", "_") or "-")
    elif a.cmd == "release":
        send_release(a)
    elif a.cmd == "offer":
        return offer_check(a)
    elif a.cmd == "arp-probe":
        return arp_probe(a)
    elif a.cmd == "redact":
        macs = [(os.environ.get("FB_ROUTER_MAC", ""), "box-mac"), (os.environ.get("FB_HOST_MAC", ""), "host-mac")]
        sys.stdout.write(redact(sys.stdin.read(), os.environ.get("FB_PREFIX", ""), macs))
    elif a.cmd in ("e1", "e2"):
        msgs = dhcp_msgs(a.pcap)
        before = parse_metrics(open(a.before).read())
        after = parse_metrics(open(a.after).read())
        if a.cmd == "e1":
            k = "releases_sent_v4"
            if k not in before or k not in after:
                res = ("BLOCKED", "releases_sent_v4 is missing from a /metrics scrape")
            else:
                led = open(a.ledger).read().splitlines() if a.ledger and os.path.exists(a.ledger) else []
                res = judge_e1(msgs, a.mac.lower(), a.since, a.server, led, a.network, after[k] - before[k])
        else:
            res = judge_e2(msgs, a.mac.lower(), a.since, a.server, before, after, json.load(open(a.health)), a.address)
        print(res[0])
        print(res[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
