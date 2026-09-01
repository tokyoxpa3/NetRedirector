# -*- coding: utf-8 -*-
"""e2e 驗證: `*.example.com` 萬用子網域匹配 (DNS 嗅探) 的整條活線路徑。

流程:
  1. 本機起最小 SOCKS5 伺服器, 記錄收到的 CONNECT 目標 (host:port)。
  2. 載入 DLL, 加規則: 任意進程 (target "*") -> hosts "*.example.com" -> PROXY。
  3. 啟動 redirector, 在本程序內解析並連線 www.example.com:80。
     預期: DNS 回應被嗅探 (填入 IP->域名對照), 連線被 wildcard 規則命中並轉入本機 SOCKS5。
  4. 斷言 SOCKS5 有收到 CONNECT (證明規則命中; 若未命中流量會走直連, SOCKS5 收不到任何東西)。

用法(需管理員 + 真實對外 DNS):
    python tests/e2e_dns_manual.py [NetRedirector.dll]
"""
import ctypes
import os
import select
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SOCKS_PORT = 11081
CONNECT_TARGETS = []
DLL_LOG = []


def recvn(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            raise ConnectionError("short read")
        buf += d
    return buf


def socks5_session(conn):
    """處理一條 SOCKS5 TCP CONNECT, 先記錄目標再嘗試轉發。

    測試只在乎 CONNECT 是否到達本機 SOCKS5 (證明流量被 wildcard 規則代理),
    因此目標會被記錄後才進行真實連線; 真實連線成敗不影響斷言。
    """
    try:
        hdr = recvn(conn, 2)
        recvn(conn, hdr[1])           # methods
        conn.sendall(b"\x05\x00")     # no-auth

        req = recvn(conn, 4)
        _, cmd, _, atyp = req
        if atyp == 1:
            host = socket.inet_ntoa(recvn(conn, 4))
        elif atyp == 3:
            ln = recvn(conn, 1)[0]
            host = recvn(conn, ln).decode("utf-8", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, recvn(conn, 16))
        else:
            conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = struct.unpack("!H", recvn(conn, 2))[0]

        CONNECT_TARGETS.append((host, port))
        DLL_LOG.append(f"CONNECT {host}:{port}")

        if cmd == 0x01:  # CONNECT
            try:
                remote = socket.create_connection((host, port), timeout=8)
                conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                remote.settimeout(3)
                conn.settimeout(3)
                end = time.time() + 2
                while time.time() < end:
                    r, _, _ = select.select([conn, remote], [], [], 1)
                    if not r:
                        continue
                    for s in r:
                        try:
                            data = s.recv(65536)
                        except OSError:
                            return
                        if not data:
                            return
                        (remote if s is conn else conn).sendall(data)
                remote.close()
            except Exception:
                try:
                    conn.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_socks5():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", SOCKS_PORT))
    srv.listen(16)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=socks5_session, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def run_test():
    dll_path = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "NetRedirector.dll")
    print(f"[dll] using {dll_path}")
    if os.path.dirname(dll_path) != os.getcwd():
        os.add_dll_directory(os.path.dirname(dll_path))

    srv = start_socks5()
    print(f"[socks5] listening 127.0.0.1:{SOCKS_PORT}")

    lib = ctypes.CDLL(dll_path)
    LOG_CB = ctypes.CFUNCTYPE(None, ctypes.c_char_p)

    def on_log(m):
        try:
            DLL_LOG.append(m.decode("utf-8", "ignore"))
        except Exception:
            pass

    log_cb = LOG_CB(on_log)
    lib.NetRedirector_SetLogCallback.argtypes = [LOG_CB]
    lib.NetRedirector_SetLogCallback(log_cb)

    lib.NetRedirector_AddProxyConfig.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                                                 ctypes.c_uint16, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_bool]
    lib.NetRedirector_AddProxyConfig.restype = ctypes.c_uint32
    proxy_id = lib.NetRedirector_AddProxyConfig(1, b"TestSocks", b"127.0.0.1", SOCKS_PORT, b"", b"", True)
    print(f"[dll] proxy_id={proxy_id}")

    lib.NetRedirector_AddRuleWithProxy.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                                   ctypes.c_int, ctypes.c_int, ctypes.c_uint32]
    lib.NetRedirector_AddRuleWithProxy.restype = ctypes.c_uint32
    # 任意進程 -> *.example.com -> PROXY (protocol 2 = BOTH, action 0 = PROXY)
    rid = lib.NetRedirector_AddRuleWithProxy(b"*", b"*.example.com", b"*", 2, 0, proxy_id)
    print(f"[dll] rule_id={rid} (target=* hosts=*.example.com action=PROXY)")

    lib.NetRedirector_Start.restype = ctypes.c_bool
    lib.NetRedirector_Stop.restype = ctypes.c_bool
    if not lib.NetRedirector_Start():
        print("[dll] Start() failed (需以管理員身分執行?)")
        srv.close()
        return 2

    try:
        time.sleep(0.5)
        # 解析 + 連線: getaddrinfo 觸發明文 DNS (被嗅探), 接著 TCP 連線被 wildcard 規則命中。
        try:
            s = socket.create_connection(("www.example.com", 80), timeout=12)
            s.close()
            print("[app] connect to www.example.com:80 OK")
        except Exception as e:
            print(f"[app] connect error: {e!r} (本測試不因此失敗, 重點是 SOCKS5 是否收到 CONNECT)")
        time.sleep(1.0)
    finally:
        lib.NetRedirector_Stop()
        print("[dll] stopped")

    srv.close()

    print("---- SOCKS5 收到的 CONNECT ----")
    for t in CONNECT_TARGETS:
        print("  ", t)

    # 斷言: 只要 SOCKS5 收到任何 CONNECT, 就代表 wildcard 規則命中並把流量代理了。
    # (若未命中, 連線走直連, SOCKS5 完全收不到任何東西)
    if CONNECT_TARGETS:
        print("\n[PASS] wildcard *.example.com 命中, 流量已轉入本機 SOCKS5")
        rc = 0
    else:
        print("\n[FAIL] SOCKS5 未收到任何 CONNECT (DNS 嗅探或規則比對未生效)")
        rc = 1

    print("---- DLL log (最後 20 條) ----")
    for line in DLL_LOG[-20:]:
        print("  ", line)
    return rc


if __name__ == "__main__":
    sys.exit(run_test())
