"""直接對 SOCKS5 代理做 UDP ASSOCIATE 的 STUN 探針。

目的：把「代理本身的 UDP 能力」與「NetRedirector 的 UDP relay」分開。

    python socks5_udp_probe.py 192.168.1.178 1080

若這裡就 0 回應，代表打洞失敗與 NetRedirector 無關 —— 這條代理的 UDP
路徑（手機 5G CGNAT）本身就不通。
"""

import socket
import struct
import sys
import time

sys.path.insert(0, ".")
from rtc_probe import (  # noqa: E402
    build_binding_request, parse_xor_mapped_address)

STUN = [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)]


def socks5_handshake(sock):
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS5 greeting rejected")


def udp_associate(sock):
    sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    head = sock.recv(4)
    if len(head) < 4 or head[1] != 0x00:
        raise RuntimeError("UDP ASSOCIATE failed: %r" % head)
    atyp = head[3]
    if atyp == 0x01:
        addr = socket.inet_ntoa(sock.recv(4))
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
    else:
        raise RuntimeError("bad ATYP %d" % atyp)
    port = struct.unpack("!H", sock.recv(2))[0]
    return addr, port


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.178"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080

    tcp = socket.create_connection((host, port), timeout=5)
    tcp.settimeout(5)
    socks5_handshake(tcp)
    relay_host, relay_port = udp_associate(tcp)
    if relay_host in ("0.0.0.0", "::"):
        relay_host = host
    print("UDP relay = %s:%d" % (relay_host, relay_port))

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(3.0)

    targets = []
    for name, p in STUN:
        try:
            ip = socket.getaddrinfo(
                name, p, socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
            targets.append((name, ip, p))
        except Exception as exc:
            print("  解析失敗 %s: %s" % (name, exc))

    for name, ip, p in targets:
        body = build_binding_request(b"\x11" * 12)
        pkt = (b"\x00\x00\x00\x01" + socket.inet_aton(ip)
               + struct.pack("!H", p) + body)
        udp.sendto(pkt, (relay_host, relay_port))

    got = 0
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            data, _ = udp.recvfrom(2048)
        except socket.timeout:
            break
        if len(data) < 10:
            continue
        atyp = data[3]
        off = 4
        if atyp == 0x01:
            off += 4 + 2
        elif atyp == 0x04:
            off += 16 + 2
        elif atyp == 0x03:
            off += 1 + data[4] + 2
        mapped = parse_xor_mapped_address(data[off:])
        if mapped:
            got += 1
            print("  回應 mapped=%s:%d" % mapped)
        else:
            print("  回應（非 STUN 或解析失敗）%d bytes" % len(data))

    print("\n結果：%d / %d 有回應" % (got, len(targets)))
    if got == 0:
        print("=> 代理的 UDP 路徑本身不通（或 STUN 被上游封鎖）")
    tcp.close()
    udp.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
