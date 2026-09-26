#!/usr/bin/env python3
"""Builds small, valid DHCPv4-over-Ethernet pcap fixtures for
dhcp-exchange-check-test.sh (issue #2). No scapy on this
host, so packets are assembled by hand from struct-packed bytes -- real
pcap files a real tcpdump decodes, not synthetic decoded-text stand-ins.
"""
import struct
import socket

PCAP_MAGIC = 0xa1b2c3d4

def ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def eth(dst: str, src: str, payload: bytes) -> bytes:
    return mac_b(dst) + mac_b(src) + struct.pack("!H", 0x0800) + payload

def mac_b(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))

def ipv4(src: str, dst: str, payload: bytes) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, 17, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    csum = ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload

def udp(sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    # Checksum 0 -- valid for IPv4 UDP (sender may omit it); avoids
    # needing the IPv4 pseudo-header just for a fixture.
    return struct.pack("!HHHH", sport, dport, length, 0) + payload

def dhcp(op: int, xid: int, flags: int, ciaddr: str, yiaddr: str,
         chaddr: str, options: bytes) -> bytes:
    hdr = struct.pack(
        "!BBBBI HH 4s4s4s4s 16s64s128s4s",
        op, 1, 6, 0, xid, 0, flags,
        socket.inet_aton(ciaddr), socket.inet_aton(yiaddr),
        socket.inet_aton("0.0.0.0"), socket.inet_aton("0.0.0.0"),
        mac_b(chaddr).ljust(16, b"\x00"), b"\x00" * 64, b"\x00" * 128,
        bytes([0x63, 0x82, 0x53, 0x63]),
    )
    return hdr + options + b"\xff"

def opt_msgtype(t: int) -> bytes:
    return bytes([53, 1, t])

def opt(code: int, val: bytes) -> bytes:
    return bytes([code, len(val)]) + val

MSG_DISCOVER, MSG_OFFER, MSG_REQUEST, MSG_ACK, MSG_NAK = 1, 2, 3, 5, 6

def discover(mac: str, xid: int) -> bytes:
    body = opt_msgtype(MSG_DISCOVER) + opt(55, bytes([1, 3, 6]))
    return dhcp(1, xid, 0x8000, "0.0.0.0", "0.0.0.0", mac, body)

def offer(mac: str, xid: int, yiaddr: str, server: str) -> bytes:
    body = opt_msgtype(MSG_OFFER) + opt(54, socket.inet_aton(server)) \
        + opt(51, struct.pack("!I", 3600)) + opt(1, socket.inet_aton("255.255.255.0"))
    return dhcp(2, xid, 0x8000, "0.0.0.0", yiaddr, mac, body)

def request(mac: str, xid: int, reqaddr: str, server: str) -> bytes:
    body = opt_msgtype(MSG_REQUEST) + opt(50, socket.inet_aton(reqaddr)) \
        + opt(54, socket.inet_aton(server))
    return dhcp(1, xid, 0x8000, "0.0.0.0", "0.0.0.0", mac, body)

def ack(mac: str, xid: int, yiaddr: str, server: str) -> bytes:
    body = opt_msgtype(MSG_ACK) + opt(54, socket.inet_aton(server)) \
        + opt(51, struct.pack("!I", 3600))
    return dhcp(2, xid, 0x8000, "0.0.0.0", yiaddr, mac, body)

def nak(mac: str, xid: int, server: str) -> bytes:
    body = opt_msgtype(MSG_NAK) + opt(54, socket.inet_aton(server))
    return dhcp(2, xid, 0x8000, "0.0.0.0", "0.0.0.0", mac, body)

def frame_c2s(mac: str, dhcp_payload: bytes) -> bytes:
    return eth("ff:ff:ff:ff:ff:ff", mac,
               ipv4("0.0.0.0", "255.255.255.255", udp(68, 67, dhcp_payload)))

def frame_s2c(server: str, mac: str, dhcp_payload: bytes) -> bytes:
    return eth("ff:ff:ff:ff:ff:ff", "52:54:00:aa:bb:cc",
               ipv4(server, "255.255.255.255", udp(67, 68, dhcp_payload)))

def write_pcap(path: str, frames: list[bytes]) -> None:
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, 1))
        for fr in frames:
            f.write(struct.pack("<IIII", 0, 0, len(fr), len(fr)))
            f.write(fr)

MAC = "da:b6:45:5b:ef:fe"
OTHER_MAC = "02:11:22:33:44:55"
SERVER = "10.200.1.2"
LEASED = "10.200.1.100"
XID = 0x6623f715
OTHER_XID = 0x11223344

def full_exchange(mac: str, xid: int) -> list[bytes]:
    return [
        frame_c2s(mac, discover(mac, xid)),
        frame_s2c(SERVER, mac, offer(mac, xid, LEASED, SERVER)),
        frame_c2s(mac, request(mac, xid, LEASED, SERVER)),
        frame_s2c(SERVER, mac, ack(mac, xid, LEASED, SERVER)),
    ]

write_pcap("dhcp-good.pcap", full_exchange(MAC, XID))

write_pcap("dhcp-stops-after-offer.pcap", [
    frame_c2s(MAC, discover(MAC, XID)),
    frame_s2c(SERVER, MAC, offer(MAC, XID, LEASED, SERVER)),
])

write_pcap("dhcp-ends-in-nak.pcap", [
    frame_c2s(MAC, discover(MAC, XID)),
    frame_s2c(SERVER, MAC, offer(MAC, XID, LEASED, SERVER)),
    frame_c2s(MAC, request(MAC, XID, LEASED, SERVER)),
    frame_s2c(SERVER, MAC, nak(MAC, XID, SERVER)),
])

# A complete, well-formed exchange -- for a MAC other than the one the
# check is asked about. Proves the check does not just look for "any
# complete exchange in the capture" (issue #2).
write_pcap("dhcp-wrong-mac.pcap", full_exchange(OTHER_MAC, OTHER_XID))

print("wrote 4 fixtures")
