"""RTC / STUN 打洞探針。

模擬 Discord 語音引擎的典型行為：**一個未 connect 的 UDP socket 同時對多個
STUN 目標發送**，然後檢查兩件事：

1. 回應的來源位址是否等於我們送去的目標位址
   （NetRedirector 的 UDP relay 回程會改寫來源；改錯就等於 WebRTC 收到
    來源不符的 STUN 回應，直接丟棄 -> ICE 永遠不完成 ->「沒有路由」）。
2. 不同目標看到的公網映射（XOR-MAPPED-ADDRESS）是否一致
   （不一致 = 每個目標一個映射 = 對稱 NAT 行為，打洞必失敗）。

用法：
    python rtc_probe.py            # 走目前引擎的規則（預設 catch-all PROXY）
    python rtc_probe.py --json     # 機器可讀輸出
"""

import json
import os
import socket
import struct
import sys
import time

MAGIC = 0x2112A442
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.nextcloud.com", 443),
]


def build_binding_request(txid):
    return struct.pack("!HHI", 0x0001, 0, MAGIC) + txid


def parse_xor_mapped_address(data):
    """回傳 ('1.2.3.4', port) 或 None。"""
    if len(data) < 20:
        return None
    msg_type, length = struct.unpack("!HH", data[:4])
    if msg_type != 0x0101:
        return None
    off = 20
    end = min(len(data), 20 + length)
    while off + 4 <= end:
        attr_type, attr_len = struct.unpack("!HH", data[off:off + 4])
        val = data[off + 4:off + 4 + attr_len]
        if attr_type == 0x0020 and len(val) >= 8:
            family = val[1]
            x_port = struct.unpack("!H", val[2:4])[0]
            port = x_port ^ (MAGIC >> 16)
            if family == 0x01:
                raw = struct.unpack("!I", val[4:8])[0] ^ MAGIC
                ip = socket.inet_ntoa(struct.pack("!I", raw))
                return (ip, port)
        off += 4 + ((attr_len + 3) & ~3)
    return None


def resolve(host, port):
    try:
        infos = socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_DGRAM)
        return infos[0][4]
    except Exception as exc:
        print("  解析失敗 %s: %s" % (host, exc))
        return None


def main():
    as_json = "--json" in sys.argv
    print("pid=%d exe=%s" % (os.getpid(), os.path.basename(sys.argv[0])))

    targets = []
    for host, port in STUN_SERVERS:
        addr = resolve(host, port)
        if addr:
            targets.append((host, addr))
    if not targets:
        print("沒有任何 STUN 目標可解析")
        return 2

    # 一個未 connect 的 socket —— Discord 的 RTC 就是這樣用的
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.settimeout(1.5)
    local_port = sock.getsockname()[1]
    print("local udp port = %d, targets = %d\n" % (local_port, len(targets)))

    txids = {}
    for host, addr in targets:
        txid = os.urandom(12)
        txids[txid] = (host, addr)
        sock.sendto(build_binding_request(txid), addr)
        time.sleep(0.05)

    rows = []
    deadline = time.time() + 6.0
    while time.time() < deadline and len(rows) < len(targets):
        try:
            data, src = sock.recvfrom(2048)
        except socket.timeout:
            break
        txid = data[8:20]
        host, target_addr = txids.get(txid, ("?", None))
        mapped = parse_xor_mapped_address(data)
        rows.append({
            "server": host,
            "target": ("%s:%d" % (target_addr[0], target_addr[1])
                       if target_addr else None),
            "reply_from": "%s:%d" % (src[0], src[1]),
            "source_ok": (bool(target_addr)
                          and src[0] == target_addr[0]
                          and src[1] == target_addr[1]),
            "mapped": "%s:%d" % mapped if mapped else None,
        })

    if as_json:
        print(json.dumps({"local_port": local_port, "results": rows,
                          "targets": [h for h, _ in targets]}, indent=2))
        return 0

    print("%-26s %-22s %-22s %-8s %s"
          % ("server", "target", "reply_from", "src_ok", "mapped"))
    print("-" * 100)
    for r in rows:
        print("%-26s %-22s %-22s %-8s %s" % (
            r["server"], r["target"], r["reply_from"],
            "OK" if r["source_ok"] else "MISMATCH", r["mapped"]))

    answered = {r["server"] for r in rows}
    missing = [h for h, _ in targets if h not in answered]
    bad_src = [r["server"] for r in rows if not r["source_ok"]]
    mapped = {r["mapped"] for r in rows if r["mapped"]}

    print("\n--- 判定 ---")
    print("有回應      : %d / %d" % (len(rows), len(targets)))
    if missing:
        print("沒回應      : %s" % ", ".join(missing))
    print("來源不符    : %s" % (", ".join(bad_src) if bad_src else "無"))
    print("映射位址數  : %d %s" % (len(mapped), sorted(mapped)))
    if len(mapped) > 1:
        print("=> 不同目標拿到不同公網映射 = 對稱 NAT 行為，打洞必失敗")
    if bad_src:
        print("=> 回程來源被改寫成別的目標 = WebRTC 會丟棄該 STUN 回應")
    if not missing and not bad_src and len(mapped) <= 1:
        print("=> STUN 層面正常")
    return 0


if __name__ == "__main__":
    sys.exit(main())
