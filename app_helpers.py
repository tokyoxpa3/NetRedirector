"""
app_helpers.py — GUI 輔助元件 (自 IntegratedApp.py 抽出)

包含:
- check_proxy_connection: 測試 SOCKS5/HTTP 代理連線
- SignalLogHandler: 把 logging 記錄轉發到 Qt signal
- NetworkMonitorWorker: 網路介面監控執行緒
- RedirectorSignals: NetRedirector 事件信號
"""

import time
import logging
import socket
import struct
import base64

import network_utils
from PySide6.QtCore import QObject, QThread, Signal


def check_proxy_connection(proxy_conf):
    """
    使用 socket 實作 SOCKS5/HTTP 協議，經由代理訪問 http://api.ipify.org
    """
    target_host = "api.ipify.org"
    target_port = 80

    ip = proxy_conf['ip']
    port = int(proxy_conf['port'])
    user = proxy_conf.get('user', '')
    pwd = proxy_conf.get('pass', '')
    ptype = proxy_conf['type']

    start_time = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)

    try:
        s.connect((ip, port))
        if ptype == "SOCKS5":
            # [修正] 只要有帳或密，就同時提供 no-auth + user/pass 兩種方法，
            # 讓伺服器決定；避免「只送 no-auth、伺服器要求認證」被回 0xFF
            if user or pwd:
                s.sendall(b'\x05\x02\x00\x02')
            else:
                s.sendall(b'\x05\x01\x00')
            resp = s.recv(2)
            if not resp or resp[0] != 0x05: raise Exception("無效的 SOCKS5 回應")
            if resp[1] == 0x02:
                if not user: raise Exception("代理需要驗證但未提供帳密")
                auth_payload = b'\x01' + bytes([len(user)]) + user.encode() + bytes([len(pwd)]) + pwd.encode()
                s.sendall(auth_payload)
                auth_resp = s.recv(2)
                if not auth_resp or auth_resp[1] != 0x00: raise Exception("帳號或密碼錯誤")
            elif resp[1] != 0x00:
                raise Exception("不支援的驗證方式")

            cmd = b'\x05\x01\x00\x03' + bytes([len(target_host)]) + target_host.encode() + struct.pack("!H", target_port)
            s.sendall(cmd)
            resp = s.recv(4)
            if not resp or resp[1] != 0x00: raise Exception(f"SOCKS5 連線目標失敗 (Code: {resp[1] if resp else 'None'})")
            addr_type = resp[3]
            if addr_type == 1: s.recv(4)
            elif addr_type == 3: s.recv(1 + s.recv(1)[0])
            elif addr_type == 4: s.recv(16)
            s.recv(2)

        elif ptype == "HTTP":
            headers = [
                f"GET http://{target_host}/ HTTP/1.1",
                f"Host: {target_host}",
                "Connection: close"
            ]
            if user and pwd:
                credentials = f"{user}:{pwd}"
                b64_cred = base64.b64encode(credentials.encode()).decode()
                headers.append(f"Proxy-Authorization: Basic {b64_cred}")
            request = "\r\n".join(headers) + "\r\n\r\n"
            s.sendall(request.encode())

        if ptype == "SOCKS5":
            http_req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n"
            s.sendall(http_req.encode())

        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk

        response_str = response.decode(errors='ignore')
        if "\r\n\r\n" in response_str:
            body = response_str.split("\r\n\r\n", 1)[1].strip()
        else:
            body = response_str.strip()

        if len(body) > 15 or len(body) < 7:
             if "407" in response_str: raise Exception("HTTP 407: 驗證失敗")
             if "403" in response_str: raise Exception("HTTP 403: 被拒絕")

        duration = int((time.time() - start_time) * 1000)
        s.close()
        return True, duration, body
    except Exception as e:
        s.close()
        return False, 0, str(e)


# --- 日誌處理 ---
class SignalLogHandler(logging.Handler, QObject):
    log_signal = Signal(str)

    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)

    def emit(self, record):
        msg = self.format(record)
        self.log_signal.emit(msg)


# --- 網路監控 ---
class NetworkMonitorWorker(QThread):
    data_updated = Signal(dict)

    def __init__(self, ping_target=network_utils.PING_TARGET):
        super().__init__()
        self.running = True
        self.ping_target = ping_target
        self.ping_enabled = True      # 是否測延遲 (由主視窗依當前分頁控制)
        self._last_latency = None      # 最近一次延遲結果，停用 ping 期間沿用

    def set_ping_target(self, target):
        self.ping_target = target

    def set_ping_enabled(self, enabled):
        self.ping_enabled = enabled

    def run(self):
        while self.running:
            interfaces = network_utils.get_system_interfaces()

            # 每輪只 ping 一次目標 (延遲對所有網卡一致，因 ping_address 未綁定來源 IP)；
            # 僅在分頁需要顯示延遲時才 ping，否則沿用上次結果，避免整輪阻塞。
            if self.ping_enabled:
                self._last_latency = network_utils.ping_address("", self.ping_target)
            latency = self._last_latency

            for name, details in interfaces.items():
                details['latency'] = latency if (latency is not None and details['connected']) else 9999

            self.data_updated.emit(interfaces)
            for _ in range(30):
                if not self.running: break
                time.sleep(0.1)

    def stop(self):
        self.running = False
        self.wait()


# --- NetRedirector 信號 ---
class RedirectorSignals(QObject):
    log_received = Signal(str)
    traffic_received = Signal(str, int, str, int, str)
