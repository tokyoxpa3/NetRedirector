import socket
import struct
import select
import threading
import logging
import time
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

# === 全局路由管理器 ===
class RouteManager:
    def __init__(self):
        self.interfaces = {} 
        self.port_bindings = {} 
        self.lock = threading.Lock()
        self.max_conns_per_ip = 50 # 稍微調高，避免頻繁切換

    # [新增/替換] 使用全量同步，而不是增量更新
    def sync_interfaces(self, new_interfaces_dict):
        """
        接收最新的介面狀態字典，並移除已經斷線的介面。
        new_interfaces_dict: 從 network_utils 掃描到的完整字典
        """
        with self.lock:
            # 1. 更新或新增介面
            for name, data in new_interfaces_dict.items():
                if name not in self.interfaces:
                    self.interfaces[name] = {'active_conns': 0}
                
                self.interfaces[name]['ip'] = data['ipv4']
                self.interfaces[name]['ipv6'] = data.get('ipv6')  # [新增] 同步 IPv6 位址 (無則 None)
                self.interfaces[name]['latency'] = data['latency']
                self.interfaces[name]['connected'] = data['connected']
            
            # 2. 清理已經不存在的介面 (處理 VPN 斷線的情況)
            # 找出目前在 self.interfaces 但不在 new_interfaces_dict 的名稱
            current_names = list(self.interfaces.keys())
            for name in current_names:
                if name not in new_interfaces_dict:
                    # 如果該介面還有活躍連線，暫時保留但標記為斷線，避免程式崩潰
                    # 但通常 socket 下一秒就會報錯，所以這裡直接刪除或標記皆可
                    if self.interfaces[name]['active_conns'] > 0:
                        self.interfaces[name]['connected'] = False
                        self.interfaces[name]['ip'] = None # 防止新的連線分配到這
                        self.interfaces[name]['ipv6'] = None # [新增] 同步清空 IPv6，避免殘留
                        logging.info(f"介面 {name} 已斷線，等待連線歸零後移除")
                    else:
                        del self.interfaces[name]
                        logging.debug(f"介面 {name} 已移除")

    def update_port_binding(self, port, iface_names):
        with self.lock:
            self.port_bindings[port] = iface_names
            logging.info(f"端口 {port} 綁定更新: {iface_names}")

    # [修改] 新增 exclude_names 參數，用於故障轉移
    def allocate_best_ip(self, server_port, exclude_names=None,
                         prefer_latency=False):
        """挑一個出口介面。

        prefer_latency=True 給 UDP 用：UDP 沒有重傳，RTT 抖動直接變成語音斷續，
        所以「延遲最低」比「連線數最少」重要得多。TCP 仍用原本的負載平衡，
        避免單一網卡被吃滿。
        """
        if exclude_names is None:
            exclude_names = set()

        with self.lock:
            allowed_names = self.port_bindings.get(server_port, [])
            if not allowed_names:
                return None, None

            candidates = []
            for name in allowed_names:
                # 如果該介面在排除名單中，直接跳過
                if name in exclude_names:
                    continue

                if name in self.interfaces:
                    data = self.interfaces[name]
                    # 必須是已連線且有 IP
                    if data.get('connected') and data.get('ip'):
                        # 簡單的負載平衡：活躍連線數 < 限制
                        if data['active_conns'] < self.max_conns_per_ip:
                            candidates.append((name, data))
            
            if not candidates:
                return None, None
            
            if prefer_latency:
                candidates.sort(
                    key=lambda x: (x[1]['latency'], x[1]['active_conns']))
            else:
                # 排序邏輯：優先選活躍數少的，其次選延遲低的
                candidates.sort(
                    key=lambda x: (x[1]['active_conns'], x[1]['latency']))
            
            best_name, best_data = candidates[0]
            best_data['active_conns'] += 1
            return best_data['ip'], best_name

    def decrement_conn(self, iface_name):
        with self.lock:
            if iface_name in self.interfaces:
                if self.interfaces[iface_name]['active_conns'] > 0:
                    self.interfaces[iface_name]['active_conns'] -= 1
                logging.debug(f"介面 {iface_name} 連線釋放")

route_manager = RouteManager()

# === SOCKS5 常數 ===
SOCKS_VERSION = 5
CMD_CONNECT = 0x01
CMD_UDP_ASSOCIATE = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
SIO_KEEPALIVE_VALS = 0x98000004

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True

class SocksProxy(StreamRequestHandler):
    def set_keepalive(self, sock, role="unknown"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, 'SIO_KEEPALIVE_VALS'):
                sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 20000, 3000))
            else:
                try:
                    sock.ioctl(SIO_KEEPALIVE_VALS, (1, 20000, 3000))
                except:
                    if hasattr(socket, 'TCP_KEEPIDLE'):
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 20)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 3)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except Exception as e:
            logging.warning(f"[{role}] Keepalive 設定失敗: {e}")

    def handle(self):
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.set_keepalive(self.connection, role="Client")
            self.handle_socks_init()
        except Exception as e:
            logging.error(f"Handle error: {e}")

    def recv_all(self, n):
        data = b''
        try:
            while len(data) < n:
                packet = self.connection.recv(n - len(data))
                if not packet: return None
                data += packet
            return data
        except Exception:
            return None

    def handle_socks_init(self):
        header = self.recv_all(2)
        if not header: return
        version, nmethods = struct.unpack("!BB", header)
        self.recv_all(nmethods)
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0x00))
        self.handle_request()

    def handle_request(self):
        header = self.recv_all(4)
        if not header: return
        version, cmd, rsv, atyp = struct.unpack("!BBBB", header)
        
        if atyp == ATYP_IPV4:
            data = self.recv_all(4)
            target_addr = socket.inet_ntoa(data) if data else None
        elif atyp == 0x04:
            data = self.recv_all(16)
            target_addr = socket.inet_ntop(socket.AF_INET6, data) if data else None
        elif atyp == 0x03:
            len_byte = self.recv_all(1)
            addr_len = ord(len_byte) if len_byte else 0
            target_addr = self.recv_all(addr_len).decode() if addr_len else None
        else:
            self.send_reply(0x08)
            return

        port_data = self.recv_all(2)
        target_port = struct.unpack("!H", port_data)[0] if port_data else 0
        
        if cmd == CMD_CONNECT and target_addr:
            self.handle_connect(target_addr, target_port)
        elif cmd == CMD_UDP_ASSOCIATE:
            # [新增] UDP ASSOCIATE。請求裡的 DST.ADDR/PORT 通常是 0.0.0.0:0
            # （客戶端還不知道自己的映射位址），所以不看 target_addr。
            self.handle_udp_associate()
        else:
            self.send_reply(0x07)

    # [修改] 這是核心修改部分：加入重試與故障轉移迴圈
    #
    # 兩層預算：單次嘗試 3 秒、整個請求 8 秒。
    # 原本是「每張網卡 5 秒、最多 16 張」＝最壞 80 秒，但引擎端等不到回應就會
    # 記一筆 "SOCKS5 handshake failed" 並丟掉連線 —— 使用者感受到的是隨機斷線。
    # 寧可早點回 0x01 讓引擎重試，也不要拖到對方放棄。
    CONNECT_TRY_TIMEOUT = 3.0
    CONNECT_TOTAL_BUDGET = 8.0

    def handle_connect(self, addr, port):
        server_port = self.server.server_address[1]
        
        # [新增] IPv6 目標支援 (ATYP 0x04)：依位址格式決定 socket family
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        
        # 用於記錄本次請求中失敗過的介面
        failed_interfaces = set()
        deadline = time.monotonic() + self.CONNECT_TOTAL_BUDGET
        
        remote = None
        current_iface_name = None
        success = False

        # 嘗試迴圈：直到成功或沒有可用介面為止
        while not success:
            if time.monotonic() >= deadline:
                logging.warning(
                    f"[Port {server_port}] 連線 {addr}:{port} 超出 "
                    f"{self.CONNECT_TOTAL_BUDGET:.0f}s 預算，放棄 "
                    f"(已試: {failed_interfaces})")
                self.send_reply(0x01)
                return

            bind_ip, iface_name = route_manager.allocate_best_ip(server_port, exclude_names=failed_interfaces)
            
            if not bind_ip:
                # 沒有可用的 IP 了，真的失敗了
                logging.error(f"[Port {server_port}] 無可用介面連線至 {addr}:{port} (已嘗試: {failed_interfaces})")
                self.send_reply(0x01) # Host unreachable
                return

            logging.info(f"嘗試經由 {iface_name} ({bind_ip}) 連線至 {addr}:{port}...")
            
            remote = socket.socket(family, socket.SOCK_STREAM)
            current_iface_name = iface_name

            try:
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # 關鍵：綁定出口 IP
                # 如果 VPN 剛斷，這裡 bind 可能會報錯 (OSError: [WinError 10049])
                if family == socket.AF_INET6:
                    # [新增] IPv6 目標：目前不支援綁定特定介面的 IPv6 位址，
                    # 使用 :: (任何介面) 綁定。若需介面級 IPv6 綁定，需讓
                    # RouteManager 同時維護各介面的 IPv6 位址。
                    remote.bind(("::", 0))
                else:
                    remote.bind((bind_ip, 0))
                
                # 短超時：快速偵測壞掉的路由，把時間留給下一張網卡
                remote.settimeout(self.CONNECT_TRY_TIMEOUT)
                
                remote.connect((addr, port))
                
                # 連線成功！
                success = True
                
                # 恢復正常的 Socket 設定
                remote.settimeout(None)
                self.set_keepalive(remote, role="Remote")
                
                # 回覆 Client
                reply = struct.pack("!BBBB", SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4)
                reply += socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
                self.connection.sendall(reply)
                
                # 開始轉發
                self.relay_data(self.connection, remote)

            except (socket.timeout, OSError, ConnectionRefusedError) as e:
                logging.warning(f"介面 {iface_name} 連線失敗 ({e})，嘗試切換下一個介面...")
                
                # 標記此介面為失敗，稍後歸還計數並關閉 Socket
                failed_interfaces.add(iface_name)
                route_manager.decrement_conn(iface_name)
                try:
                    remote.close()
                except:
                    pass
                remote = None
                # Continue loop -> 會回到 allocate_best_ip，這次會避開 failed_interfaces
                
            except Exception as e:
                # 其他未預期的錯誤，直接終止
                logging.error(f"嚴重錯誤 ({iface_name}): {e}")
                failed_interfaces.add(iface_name)
                route_manager.decrement_conn(iface_name)
                if remote: remote.close()
                break

        # 迴圈結束後的清理 (只有在成功連線結束後，才需要在這裡 decrement，失敗的情況在迴圈內已處理)
        if success and current_iface_name:
            route_manager.decrement_conn(current_iface_name)
            if remote:
                try: remote.close()
                except: pass

    def relay_data(self, client, remote):
        try:
            while True:
                r, _, _ = select.select([client, remote], [], [])
                if client in r:
                    data = client.recv(4096)
                    if not data: break
                    remote.sendall(data)
                if remote in r:
                    data = remote.recv(4096)
                    if not data: break
                    client.sendall(data)
        except ConnectionResetError:
            pass
        except Exception as e:
            if "Software caused connection abort" not in str(e):
                logging.debug(f"Relay loop ended: {e}")

    def send_reply(self, code):
        try:
            reply = struct.pack("!BBBB", SOCKS_VERSION, code, 0x00, ATYP_IPV4) + b'\x00'*6
            self.connection.sendall(reply)
        except: pass

    # ================= [新增] SOCKS5 UDP ASSOCIATE (CMD 0x03) =================
    #
    # 只新增分支，不動 CONNECT：cmd 不是 0x01/0x03 時仍然回 0x07，與原本一致。
    #
    # 出口綁定是這裡最關鍵的一點：UDP socket 必須 bind 到 VPN 虛擬網卡的 IP。
    # 否則 sendto 會依路由表挑來源位址，而本機實體網卡的 metric(1) 優先於
    # VPN 網卡的 metric(10)，封包就會繞過 VPN 從真實 IP 出去 —— 也就是說
    # 「hub 看起來能用 UDP」但實際上完全沒走 VPN，比直接失敗更糟。
    #
    # 實測依據：ping -S 10.211.1.67 8.8.8.8 成功（45ms，走 VPN 隧道），
    # 而 ping -S 192.168.1.200 走實體網卡是 6ms，兩者路徑確實不同。

    UDP_IDLE_TIMEOUT = 120.0   # 秒；沒有任何封包就往生，避免殭屍 session 佔用介面配額

    # 出口失效判定：送出之後「完全沒有回應」多久就判定這張網卡死了。
    # VPNGate 的免費節點隨時會斷，但 UDP 沒有重傳也沒有 RST，只能靠「沒有回應」推測。
    #
    # 門檻用「時間」為主、封包數為輔，而不是像引擎那樣等 20 個封包：
    # 語音是 50pps，20 個封包只花 0.4 秒；但 Discord 的握手探測是「8 秒才一個」，
    # 等 20 個要 160 秒 —— 使用者感受到的就是「retry 好幾次才連上」。
    # 改成「2 個封包 + 靜默 4 秒」，握手場景 8 秒內就會換卡，語音場景 4 秒。
    UDP_FAILOVER_SILENCE = 4.0
    UDP_FAILOVER_MIN_SENT = 2
    UDP_FAILOVER_MAX_SWITCHES = 4      # 上限：避免「目標本來就不回」時無限換卡
    UDP_SOCK_BUF = 1 << 20     # 1 MB：吸收語音/遊戲的突發封包，避免核心丟棄

    def _open_udp_out_socket(self, bind_ip):
        """建立綁在指定出口 IP 的 UDP socket。"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, self.UDP_SOCK_BUF)
            except OSError:
                pass
        s.bind((bind_ip, 0))
        s.setblocking(False)
        return s

    def handle_udp_associate(self):
        server_port = self.server.server_address[1]
        # UDP 優先挑延遲最低的介面（不是連線數最少的）
        bind_ip, iface_name = route_manager.allocate_best_ip(
            server_port, prefer_latency=True)
        if not bind_ip:
            logging.error(f"[Port {server_port}] UDP ASSOCIATE 無可用介面")
            self.send_reply(0x01)   # Host unreachable
            return

        client_sock = None
        try:
            # --- 客戶端面 ---
            # 綁 0.0.0.0：同機（loopback）與區網其他裝置都能送進來。
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_sock.bind(("0.0.0.0", 0))
            client_sock.setblocking(False)
            any_ip, client_port = client_sock.getsockname()

            # 回給客戶端的 BND 必須是「客戶端實際連進來的本機位址」，不是出口位址。
            # 這一點是關鍵：NR 的 WinDivert 過濾器排除 127/8 目的地，所以
            # loopback 客戶端拿到 127.0.0.1 之後，雙向封包都完全繞過攔截。
            # 舊版把 BND 填成 VPN 網卡位址（10.211.1.x），那些封包會被攔下來
            # 再依規則重新導向，導致 hub 自己的 UDP 被繞回自己 —— 表現就是
            # 引擎端「UDP ASSOCIATE 成功但永遠收不到任何回應」。
            try:
                bnd_ip = self.connection.getsockname()[0]
            except OSError:
                bnd_ip = any_ip
            if not bnd_ip or bnd_ip == "0.0.0.0":
                bnd_ip = any_ip

            # 回覆 BND.ADDR/BND.PORT —— 客戶端之後把 UDP 封包送到這裡。
            # 出口 socket 由 relay_udp 管理，因為它可能中途換掉（見 failover）。
            self.connection.sendall(
                struct.pack("!BBBB", SOCKS_VERSION, 0x00, 0x00, ATYP_IPV4)
                + socket.inet_aton(bnd_ip)
                + struct.pack("!H", client_port)
            )
            self.relay_udp(client_sock, server_port, bind_ip, iface_name)
        except Exception as e:
            logging.warning(f"UDP ASSOCIATE 結束 ({iface_name}): {e}")
        finally:
            if client_sock:
                try:
                    client_sock.close()
                except OSError:
                    pass

    def relay_udp(self, client_sock, server_port, bind_ip, iface_name):
        """在控制連線存活期間，雙向搬運 UDP 封包。

        兩個 socket 分工，不再靠「第一次收到的來源」猜誰是客戶端：
        * client_sock 只會收到客戶端送來的 SOCKS5 UDP 封包
        * out_sock（綁在 VPN 網卡上）只會收到目標回來的原始封包

        舊版用單一 socket 同時收兩邊、再用來源位址區分，只要第一個封包判斷錯，
        整個 session 就會把客戶端封包當成目標回應原樣彈回去。拆開後不可能搞錯。

        出口熱切換：VPNGate 的節點隨時會斷，而 UDP 沒有重傳、也沒有 RST，
        唯一能觀察到的就是「送出去卻沒有回應」。偵測到之後在這裡換一張網卡
        重新綁定 out_sock，client_sock 與 BND 完全不變 —— 客戶端（引擎）不會
        察覺，只會感覺到一次短暫停頓。若交給引擎去判斷，它要等 15 秒才放棄並
        重撥整個 association，主觀感受就是「連線一直斷」。
        """
        client_addr = None
        last_active = time.monotonic()
        sent_since_reply = 0
        tried_ifaces = {iface_name} if iface_name else set()
        # pending_since：自上次收到回應以來，「第一顆沒有被回應的封包」的時間點。
        # 用它而不是「最後一次送出時間」，才不會被持續送出的封包一直把計時器往後推。
        pending_since = None
        switch_count = 0
        cooldown_until = 0.0

        out_sock = None
        out6_sock = None
        try:
            out_sock = self._open_udp_out_socket(bind_ip)
            out_ip, out_port = out_sock.getsockname()
            logging.info(
                f"UDP ASSOCIATE 出口 {iface_name} ({out_ip}:{out_port})")
        except OSError as e:
            logging.warning(f"UDP 出口 socket 建立失敗 ({iface_name}): {e}")
            return

        def ensure_v6_socket():
            """IPv6 目標用獨立 socket（延遲建立）。

            綁 :: 走本機原生 IPv6 —— 與 handle_connect 對 IPv6 目標的處理一致
            （那裡也是 bind(("::", 0))）。VPNGate 節點是純 IPv4，本來就沒有
            IPv6 出口可綁，所以這裡不嘗試綁 VPN 網卡。
            """
            nonlocal out6_sock
            if out6_sock is not None:
                return out6_sock
            try:
                s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
                    try:
                        s.setsockopt(socket.SOL_SOCKET, opt, self.UDP_SOCK_BUF)
                    except OSError:
                        pass
                s.bind(("::", 0))
                s.setblocking(False)
                out6_sock = s
                logging.info("UDP 已啟用 IPv6 出口 (原生 IPv6)")
            except OSError as e:
                logging.debug(f"IPv6 出口 socket 建立失敗: {e}")
                out6_sock = None
            return out6_sock

        try:
            while True:
                try:
                    watch = [self.connection, client_sock, out_sock]
                    if out6_sock is not None:
                        watch.append(out6_sock)
                    readable, _, _ = select.select(watch, [], [], 1.0)
                except (OSError, ValueError):
                    break

                if self.connection in readable:
                    # 控制連線是 TCP，客戶端關閉它代表這個 UDP session 結束
                    try:
                        if not self.connection.recv(1):
                            break
                    except Exception:
                        break

                if client_sock in readable:
                    try:
                        data, src = client_sock.recvfrom(65535)
                    except (BlockingIOError, ConnectionResetError):
                        data, src = None, None
                    except OSError:
                        break
                    if data:
                        last_active = time.monotonic()
                        client_addr = src
                        # 客戶端 -> 目標：剝掉 SOCKS5 UDP header 再送出
                        parsed = self.parse_udp_datagram(data)
                        if parsed:
                            target, payload = parsed
                            if ':' in target[0]:
                                sock = ensure_v6_socket()
                            else:
                                sock = out_sock
                            if sock is not None:
                                try:
                                    sock.sendto(payload, target)
                                    # 只把 IPv4 送出算進 failover 判定：IPv6 走的是
                                    # 原生線路，跟 VPN 出口的死活無關，混在一起算
                                    # 會讓 IPv6 的靜默誤觸發 VPN 換卡。
                                    if sock is out_sock:
                                        sent_since_reply += 1
                                        if pending_since is None:
                                            pending_since = time.monotonic()
                                except OSError as e:
                                    logging.debug(
                                        f"UDP sendto {target} 失敗: {e}")

                for rsock in (out_sock, out6_sock):
                    if rsock is None or rsock not in readable:
                        continue
                    try:
                        data, src = rsock.recvfrom(65535)
                    except (BlockingIOError, ConnectionResetError):
                        continue
                    except OSError:
                        data = None
                    if data and client_addr:
                        last_active = time.monotonic()
                        sent_since_reply = 0
                        pending_since = None
                        tried_ifaces.clear()        # 這張網卡活著，重新開放其他候選
                        # 目標 -> 客戶端：補上 SOCKS5 UDP header 再送回
                        header = self.build_udp_header(src)
                        if header:
                            try:
                                client_sock.sendto(header + data, client_addr)
                            except OSError as e:
                                logging.debug(f"UDP 回送 {client_addr} 失敗: {e}")

                # --- 出口失效偵測與熱切換 ---
                now = time.monotonic()
                if (pending_since is not None
                        and sent_since_reply >= self.UDP_FAILOVER_MIN_SENT
                        and now - pending_since >= self.UDP_FAILOVER_SILENCE
                        and now >= cooldown_until):
                    if switch_count >= self.UDP_FAILOVER_MAX_SWITCHES:
                        # 已經換到上限：目標本身不回的可能性更高，停止再換
                        logging.debug(
                            f"UDP 已熱切換 {switch_count} 次，停止再換卡 ({iface_name})")
                        pending_since = None
                    else:
                        new_ip, new_iface = route_manager.allocate_best_ip(
                            server_port, exclude_names=tried_ifaces,
                            prefer_latency=True)
                        new_sock = None
                        if new_ip and new_iface:
                            try:
                                new_sock = self._open_udp_out_socket(new_ip)
                            except OSError as e:
                                logging.debug(f"切換到 {new_iface} 失敗: {e}")
                        if new_sock:
                            old_iface = iface_name
                            try:
                                out_sock.close()
                            except OSError:
                                pass
                            out_sock = new_sock
                            iface_name = new_iface
                            tried_ifaces.add(new_iface)
                            if old_iface:
                                route_manager.decrement_conn(old_iface)
                            switch_count += 1
                            logging.warning(
                                f"UDP 出口 {old_iface} 靜默 "
                                f"{now - pending_since:.1f}s / "
                                f"{sent_since_reply} 個封包，"
                                f"熱切換到 {new_iface} ({new_ip})")
                        # 無論成功與否都重新計時，避免同一輪反覆重試
                        pending_since = None
                        sent_since_reply = 0
                        cooldown_until = now + 6.0

                if now - last_active > self.UDP_IDLE_TIMEOUT:
                    logging.debug("UDP session 閒置逾時，關閉")
                    break
        finally:
            for s in (out_sock, out6_sock):
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass
            if iface_name:
                route_manager.decrement_conn(iface_name)

    def parse_udp_datagram(self, data):
        """解析 RFC 1928 §7 的 UDP 請求標頭，回傳 ((addr, port), payload)。"""
        if len(data) < 4:
            return None
        if data[2] != 0:
            return None                     # FRAG != 0：不支援分片，直接丟棄
        atyp = data[3]
        offset = 4

        if atyp == ATYP_IPV4:
            if len(data) < offset + 6:
                return None
            addr = socket.inet_ntoa(data[offset:offset + 4])
            offset += 4
        elif atyp == ATYP_DOMAIN:
            if len(data) < offset + 1:
                return None
            name_len = data[offset]
            offset += 1
            if len(data) < offset + name_len + 2:
                return None
            try:
                name = data[offset:offset + name_len].decode('idna')
            except Exception:
                return None
            offset += name_len
            # 這個 socket 是 AF_INET，域名要先解析成 IPv4
            try:
                infos = socket.getaddrinfo(
                    name, 0, socket.AF_INET, socket.SOCK_DGRAM)
                addr = infos[0][4][0]
            except Exception:
                return None
        elif atyp == ATYP_IPV6:
            if len(data) < offset + 18:
                return None
            addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
            offset += 16
        else:
            return None

        if len(data) < offset + 2:
            return None
        port = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2
        return (addr, port), data[offset:]

    def build_udp_header(self, src):
        """把來源位址包成 SOCKS5 UDP 回應標頭（RSV + FRAG + ATYP + ADDR + PORT）。

        必須同時支援 IPv4 與 IPv6：引擎端對 IPv6 用的是 22 bytes 標頭
        （4 + 16 + 2），若這裡只會組 IPv4，IPv6 的回程會被引擎丟掉。
        """
        host = src[0]
        try:
            if ':' in host:
                packed = socket.inet_pton(socket.AF_INET6, host)
                atyp = ATYP_IPV6
            else:
                packed = socket.inet_aton(host)
                atyp = ATYP_IPV4
        except OSError:
            return None
        return (b'\x00\x00\x00' + bytes([atyp]) + packed
                + struct.pack("!H", src[1]))

class ServerController:
    def __init__(self):
        self.servers = {} 

    def start_port(self, port):
        if port in self.servers: return True
        try:
            server = ThreadingTCPServer(("0.0.0.0", port), SocksProxy)
            thread = threading.Thread(target=server.serve_forever)
            thread.daemon = True
            thread.start()
            self.servers[port] = server
            logging.info(f"服務器已啟動: Port {port}")
            return True
        except OSError as e:
            logging.error(f"端口 {port} 被佔用或權限不足: {e}")
            return False
        except Exception as e:
            logging.error(f"無法啟動 Port {port}: {e}")
            return False

    def stop_port(self, port):
        if port in self.servers:
            try:
                self.servers[port].shutdown()
                self.servers[port].server_close()
                del self.servers[port]
                logging.info(f"服務器已停止: Port {port}")
            except Exception as e:
                logging.error(f"停止 Port {port} 時發生錯誤: {e}")

    def stop_all(self):
        # 平行停止所有監聽端口：每個 shutdown() 最多阻塞一個 poll interval
        # (約 0.5 秒)。若按序停止，N 個端口會累加出 N×0.5 秒的關閉延遲；
        # 平行化後總時間只等最慢的那一個。各端口使用獨立 socket 與
        # serve_forever 執行緒，彼此無共享狀態，並行關閉安全。
        ports = list(self.servers.keys())
        threads = [threading.Thread(target=self.stop_port, args=(p,), daemon=True) for p in ports]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

server_controller = ServerController()