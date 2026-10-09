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

def write_pcap(path: str, frames: list) -> None:
    """frames: bytes (timestamp 0) or (seconds, bytes) for group C's
    timing rules (#23)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, 1))
        for fr in frames:
            ts = 0.0
            if isinstance(fr, tuple):
                ts, fr = fr
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(fr), len(fr)))
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

# Group C (#23) fixtures for dhcp_message_log, with real timestamps.
PARENT = "52:54:00:12:34:56"
CID = bytes.fromhex("000102030405060708")
OTHER_CID = bytes.fromhex("00aabbccddeeff0011")
ROGUE = "10.200.1.240"
MSG_DECLINE = 4

def with_cid(payload: bytes, cid: bytes) -> bytes:
    # option 61 goes before the end option dhcp() appended
    return payload[:-1] + opt(61, cid) + b"\xff"

def renew(mac: str, xid: int, ciaddr: str) -> bytes:
    return dhcp(1, xid, 0, ciaddr, "0.0.0.0", mac, opt_msgtype(MSG_REQUEST))

def decline(mac: str, xid: int, addr: str, server: str) -> bytes:
    body = opt_msgtype(MSG_DECLINE) + opt(50, socket.inet_aton(addr)) + opt(54, socket.inet_aton(server))
    return dhcp(1, xid, 0, "0.0.0.0", "0.0.0.0", mac, body)

def unicast_c2s(mac: str, src: str, dst: str, payload: bytes) -> bytes:
    return eth("52:54:00:aa:bb:cc", mac, ipv4(src, dst, udp(68, 67, payload)))

# Client-id identity behind a shared parent MAC (ipvlan): three DISCOVERs
# 4.2 s and 7.9 s apart, an OFFER and ACK that carry no option 61 (tied by
# xid), and a second client on the same parent MAC that must not match.
X1, X2 = 0x0c100001, 0x0c100002
write_pcap("dhcp-c-retransmit.pcap", [
    (100.0, frame_c2s(PARENT, with_cid(discover(PARENT, X1), CID))),
    (101.0, frame_c2s(PARENT, with_cid(discover(PARENT, X2), OTHER_CID))),
    (104.2, frame_c2s(PARENT, with_cid(discover(PARENT, X1), CID))),
    (112.1, frame_c2s(PARENT, with_cid(discover(PARENT, X1), CID))),
    (114.3, frame_s2c(SERVER, PARENT, offer(PARENT, X1, LEASED, SERVER))),
    (114.4, frame_c2s(PARENT, with_cid(request(PARENT, X1, LEASED, SERVER), CID))),
    (114.5, frame_s2c(SERVER, PARENT, ack(PARENT, X1, LEASED, SERVER))),
])

# MAC identity: bound at 1000.5, a unicast renewal at 1060 with no answer
# (source down), a broadcast rebind at 1105 answered by an ACK.
X3, X4, X5 = 0x0c200001, 0x0c200002, 0x0c200003
write_pcap("dhcp-c-unanswered-request.pcap", [
    (1000.0, frame_c2s(MAC, discover(MAC, X3))),
    (1000.2, frame_s2c(SERVER, MAC, offer(MAC, X3, LEASED, SERVER))),
    (1000.3, frame_c2s(MAC, request(MAC, X3, LEASED, SERVER))),
    (1000.5, frame_s2c(SERVER, MAC, ack(MAC, X3, LEASED, SERVER))),
    (1060.0, unicast_c2s(MAC, LEASED, SERVER, renew(MAC, X4, LEASED))),
    (1105.0, frame_c2s(MAC, renew(MAC, X5, LEASED))),
    (1105.1, frame_s2c(SERVER, MAC, ack(MAC, X5, LEASED, SERVER))),
])

# Two servers offer, the client declines the address it was given and a
# later REQUEST is NAKed.
X6, X7 = 0x0c300001, 0x0c300002
write_pcap("dhcp-c-decline-nak.pcap", [
    (10.0, frame_c2s(MAC, discover(MAC, X6))),
    (10.1, frame_s2c(SERVER, MAC, offer(MAC, X6, LEASED, SERVER))),
    (10.2, frame_s2c(ROGUE, MAC, offer(MAC, X6, "10.200.1.241", ROGUE))),
    (10.3, frame_c2s(MAC, request(MAC, X6, LEASED, SERVER))),
    (10.4, frame_s2c(SERVER, MAC, ack(MAC, X6, LEASED, SERVER))),
    (11.5, frame_c2s(MAC, decline(MAC, X6, LEASED, SERVER))),
    (12.0, frame_c2s(MAC, request(MAC, X7, LEASED, SERVER))),
    (12.1, frame_s2c(SERVER, MAC, nak(MAC, X7, SERVER))),
])

# A copy taken while tcpdump was writing: the good exchange with its last
# record cut short.
write_pcap("dhcp-c-partial.pcap", full_exchange(MAC, XID))
with open("dhcp-c-partial.pcap", "r+b") as f:
    f.seek(0, 2)
    f.truncate(f.tell() - 100)

print("wrote 8 fixtures")
