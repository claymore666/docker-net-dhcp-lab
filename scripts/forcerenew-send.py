#!/usr/bin/env python3
"""Send one DHCPFORCERENEW as a raw Ethernet frame (lab #21, scenario F8-forcerenew).

Runs on the source VM's segment leg: a raw frame claims no address and
binds no port, so the real server keeps port 67 and its own ARP answers.
Modes (RFC 3203, RFC 6704 3.1): unsigned has no option 90; badkey signs
with the wrong key at replay ack+1; signed signs with the nonce at ack+2.
--dry-run FILE writes the frame to FILE instead. Standard library only.
"""
import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys

MODES = ("unsigned", "badkey", "signed")


def mac_bytes(s):
    b = bytes.fromhex(s.replace(":", ""))
    if len(b) != 6:
        raise ValueError("not a MAC: %r" % s)
    return b


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def auth_option(replay, value_type, value):
    # RFC 6704 3.1.2/3.1.3: protocol 3, algorithm 1 (HMAC-MD5), RDM 0.
    body = bytes([3, 1, 0]) + struct.pack("!Q", replay) + bytes([value_type]) + value
    return bytes([90, len(body)]) + body


def dhcp_payload(args, xid, replay, digest):
    hdr = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s4s",
        2, 1, 6, 0, xid, 0, 0,
        socket.inet_aton(args.dst_ip),  # ciaddr: the leased address
        b"\0" * 4, b"\0" * 4, b"\0" * 4,
        mac_bytes(args.chaddr).ljust(16, b"\0"),
        b"\0" * 64, b"\0" * 128, b"\x63\x82\x53\x63")
    opts = bytes([53, 1, 9, 54, 4]) + socket.inet_aton(args.src_ip)
    if args.client_id:
        cid = bytes.fromhex(args.client_id.replace(":", ""))
        opts += bytes([61, len(cid)]) + cid
    if digest is not None:
        opts += auth_option(replay, 2, digest)
    msg = hdr + opts + b"\xff"
    # BOOTP's 300-octet minimum (RFC 951); the HMAC covers the padding too.
    return msg.ljust(300, b"\0")


def build_payload(args, xid):
    if args.mode == "unsigned":
        return dhcp_payload(args, xid, 0, None), 0
    nonce = bytes.fromhex(args.nonce)
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    replay = args.ack_replay + (1 if args.mode == "badkey" else 2)
    key = nonce if args.mode == "signed" else bytes(b ^ 0xFF for b in nonce)
    # RFC 6704 3.1.4 / RFC 3118 section 5: the HMAC covers the whole
    # message with the digest field zeroed (hops and giaddr are zero).
    zeroed = dhcp_payload(args, xid, replay, b"\0" * 16)
    digest = hmac.new(key, zeroed, hashlib.md5).digest()
    return dhcp_payload(args, xid, replay, digest), replay


def frame(args, src_mac, payload):
    udp_len = 8 + len(payload)
    src, dst = socket.inet_aton(args.src_ip), socket.inet_aton(args.dst_ip)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_len)
    udp = struct.pack("!HHHH", 67, 68, udp_len, 0) + payload
    uc = csum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", uc) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, xid16(), 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return mac_bytes(args.dst_mac) + src_mac + b"\x08\x00" + ip + udp


def xid16():
    return struct.unpack("!H", os.urandom(2))[0]


def main(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iface", default="eth1")
    p.add_argument("--dst-mac", required=True, help="the client's MAC from the source's neighbour table")
    p.add_argument("--dst-ip", required=True, help="the leased address")
    p.add_argument("--src-ip", required=True, help="the server identifier (option 54)")
    p.add_argument("--src-mac", help="default: the interface's own MAC")
    p.add_argument("--chaddr", required=True, help="the lease's hardware address")
    p.add_argument("--client-id", default="", help="option 61 as hex, when the client sent one")
    p.add_argument("--mode", required=True, choices=MODES)
    p.add_argument("--nonce", default="", help="16-byte nonce as hex (badkey, signed)")
    p.add_argument("--ack-replay", type=int, default=0, help="the replay value of the ACK's option 90")
    p.add_argument("--xid", type=lambda s: int(s, 0), help="default: random")
    p.add_argument("--dry-run", metavar="FILE")
    args = p.parse_args(argv)
    xid = args.xid if args.xid is not None else struct.unpack("!I", os.urandom(4))[0]
    payload, replay = build_payload(args, xid)
    if args.src_mac:
        src_mac = mac_bytes(args.src_mac)
    else:
        with open("/sys/class/net/%s/address" % args.iface) as f:
            src_mac = mac_bytes(f.read().strip())
    fr = frame(args, src_mac, payload)
    if args.dry_run:
        with open(args.dry_run, "wb") as f:
            f.write(fr)
    else:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((args.iface, 0))
        if s.send(fr) != len(fr):
            raise OSError("short send")
        s.close()
    print("forcerenew mode=%s xid=0x%08x replay=%d dst=%s/%s len=%d" % (args.mode, xid, replay, args.dst_mac, args.dst_ip, len(fr)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
