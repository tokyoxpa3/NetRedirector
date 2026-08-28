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
    def allocate_best_ip(self, server_port, exclude_names=None):
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
            
            # 排序邏輯：優先選活躍數少的，其次選延遲低的
            candidates.sort(key=lambda x: (x[1]['active_conns'], x[1]['latency']))
            
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
ATYP_IPV4 = 0x01
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
        else:
            self.send_reply(0x07)

    # [修改] 這是核心修改部分：加入重試與故障轉移迴圈
    def handle_connect(self, addr, port):
        server_port = self.server.server_address[1]
        
        # [新增] IPv6 目標支援 (ATYP 0x04)：依位址格式決定 socket family
        family = socket.AF_INET6 if ':' in addr else socket.AF_INET
        
        # 用於記錄本次請求中失敗過的介面
        failed_interfaces = set()
        
        remote = None
        current_iface_name = None
        success = False

        # 嘗試迴圈：直到成功或沒有可用介面為止
        while not success:
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
                
                # 設定短超時，快速偵測壞掉的路由
                # 建議設短一點 (例如 5秒)，讓切換更順暢
                remote.settimeout(5) 
                
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