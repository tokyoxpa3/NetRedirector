import ctypes
import os
import sys
import time
from ctypes import Structure, c_uint32, c_uint16, c_char, c_char_p, c_bool, c_int, c_void_p, POINTER, CFUNCTYPE

# --- 定義常數與枚舉 (對應 NetRedirector.h) ---

class ProxyType:
    HTTP = 0
    SOCKS5 = 1

class RuleAction:
    PROXY = 0
    DIRECT = 1
    BLOCK = 2

class RuleProtocol:
    TCP = 0
    UDP = 1
    BOTH = 2

# --- 定義 C 結構體 (必須與 .h 檔完全一致) ---

class PROXY_CONFIG(Structure):
    pass

PROXY_CONFIG._fields_ = [
    ("proxy_id", c_uint32),
    ("name", c_char * 256),
    ("proxy_ip", c_char * 64),
    ("proxy_port", c_uint16),
    ("proxy_type", c_int),      # enum 其實就是 int
    ("username", c_char * 256),
    ("password", c_char * 256),
    ("enabled", c_bool),
    ("next", POINTER(PROXY_CONFIG))
]

# --- 定義回調函數類型 ---
# LogCallback: void (*)(const char* message)
LOG_CALLBACK_TYPE = CFUNCTYPE(None, c_char_p)

# ConnectionCallback: void (*)(const char* process, DWORD pid, const char* ip, UINT16 port, const char* info)
CONN_CALLBACK_TYPE = CFUNCTYPE(None, c_char_p, c_uint32, c_char_p, c_uint16, c_char_p)

class NetRedirectorWrapper:
    def __init__(self, dll_path="NetRedirector.dll"):
        dll_abs_path = os.path.abspath(dll_path)
        
        if not os.path.exists(dll_abs_path):
            raise FileNotFoundError(f"DLL not found at {dll_abs_path}")
        
        # 加載 DLL
        try:
            self.lib = ctypes.CDLL(dll_abs_path)
        except OSError as e:
            print("Error loading DLL. Make sure windivert.dll is also in the same folder.")
            raise e

        # --- 設置函數參數類型 (Argtypes) 與 返回類型 (Restype) ---
        
        # UINT32 NetRedirector_AddRule(...)
        self.lib.NetRedirector_AddRule.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int]
        self.lib.NetRedirector_AddRule.restype = c_uint32

        # UINT32 NetRedirector_AddProxyConfig(...)
        self.lib.NetRedirector_AddProxyConfig.argtypes = [c_int, c_char_p, c_char_p, c_uint16, c_char_p, c_char_p, c_bool]
        self.lib.NetRedirector_AddProxyConfig.restype = c_uint32

        # BOOL NetRedirector_SetProxyConfig(...) (設定全局/預設代理)
        self.lib.NetRedirector_SetProxyConfig.argtypes = [c_int, c_char_p, c_uint16, c_char_p, c_char_p]
        self.lib.NetRedirector_SetProxyConfig.restype = c_bool

        # void NetRedirector_SetLogCallback(...)
        self.lib.NetRedirector_SetLogCallback.argtypes = [LOG_CALLBACK_TYPE]
        self.lib.NetRedirector_SetLogCallback.restype = None

        # void NetRedirector_SetConnectionCallback(...)
        self.lib.NetRedirector_SetConnectionCallback.argtypes = [CONN_CALLBACK_TYPE]
        self.lib.NetRedirector_SetConnectionCallback.restype = None

        # BOOL NetRedirector_Start(void)
        self.lib.NetRedirector_Start.argtypes = []
        self.lib.NetRedirector_Start.restype = c_bool

        # BOOL NetRedirector_Stop(void)
        self.lib.NetRedirector_Stop.argtypes = []
        self.lib.NetRedirector_Stop.restype = c_bool

        # --- [新增] 定義 PID 規則相關函數 ---
        try:
            # UINT32 NetRedirector_AddRuleByPID(DWORD pid, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
            self.lib.NetRedirector_AddRuleByPID.argtypes = [c_uint32, c_char_p, c_char_p, c_int, c_int, c_uint32]
            self.lib.NetRedirector_AddRuleByPID.restype = c_uint32
            self._has_pid_support = True
        except AttributeError:
            print("[Warning] NetRedirector_AddRuleByPID not found in DLL. PID rules will not work.")
            self._has_pid_support = False

        # --- [新增] 能力探測一次 (GUI 不得再散落 hasattr 檢查) ---
        self._has_add_rule_with_proxy = hasattr(self.lib, 'NetRedirector_AddRuleWithProxy')
        if self._has_add_rule_with_proxy:
            self.lib.NetRedirector_AddRuleWithProxy.argtypes = [c_char_p, c_char_p, c_char_p, c_int, c_int, c_uint32]
            self.lib.NetRedirector_AddRuleWithProxy.restype = c_uint32

        self._has_edit_rule_with_proxy = hasattr(self.lib, 'NetRedirector_EditRuleWithProxy')
        if self._has_edit_rule_with_proxy:
            self.lib.NetRedirector_EditRuleWithProxy.argtypes = [c_uint32, c_char_p, c_char_p, c_char_p, c_int, c_int, c_uint32]
            self.lib.NetRedirector_EditRuleWithProxy.restype = c_bool

        self._has_delete_rule = hasattr(self.lib, 'NetRedirector_DeleteRule')
        if self._has_delete_rule:
            self.lib.NetRedirector_DeleteRule.argtypes = [c_uint32]
            self.lib.NetRedirector_DeleteRule.restype = c_bool

        # 保持對 callback 的引用，防止 Python 垃圾回收機制(GC)將其清除導致 C 端崩潰
        self._log_cb_ref = None
        self._conn_cb_ref = None

    def set_log_callback(self, python_func):
        """
        python_func(message: str)
        """
        def c_callback(msg_ptr):
            if msg_ptr:
                msg = msg_ptr.decode('utf-8', errors='ignore')
                python_func(msg)

        # 將 Python 函數包裝成 C 函數指針
        self._log_cb_ref = LOG_CALLBACK_TYPE(c_callback)
        self.lib.NetRedirector_SetLogCallback(self._log_cb_ref)
            # --- [新增] 添加 PID 規則的 Python 方法 ---
    def add_rule_by_pid(self, pid, target_hosts="*", target_ports="*", protocol=RuleProtocol.BOTH, action=RuleAction.PROXY, proxy_id=0):
        if not self._has_pid_support:
            print("DLL does not support AddRuleByPID")
            return 0
            
        return self.lib.NetRedirector_AddRuleByPID(
            pid,
            target_hosts.encode('utf-8'),
            target_ports.encode('utf-8'),
            protocol,
            action,
            proxy_id
        )

    def set_connection_callback(self, python_func, throttle_ms=200):
        """
        python_func(process_name, pid, dest_ip, dest_port, proxy_info)

        throttle_ms: 連線回呼的轉送間隔（毫秒）。此回呼在 C 的封包處理緒上同步
        執行，BT 等高併發情境每秒可觸發數百次；每轉送一次都要跨進 Python 拿 GIL
        並 emit Qt 訊號，會拖慢封包轉發、卡住整個轉發器。限流後封包緒幾乎立即
        返回，GUI 只收到每 throttle_ms 最多一次的更新（流量監看綽綽有餘）。
        """
        interval = max(0.0, float(throttle_ms)) / 1000.0
        state = {'last': 0.0}

        def c_callback(proc_ptr, pid, ip_ptr, port, info_ptr):
            now = time.monotonic()
            if interval > 0 and now - state['last'] < interval:
                return  # 限流：高併發下不逐條跨 GIL / emit
            state['last'] = now
            proc = proc_ptr.decode('utf-8', errors='ignore') if proc_ptr else "Unknown"
            ip = ip_ptr.decode('utf-8', errors='ignore') if ip_ptr else "0.0.0.0"
            info = info_ptr.decode('utf-8', errors='ignore') if info_ptr else ""
            python_func(proc, pid, ip, port, info)

        self._conn_cb_ref = CONN_CALLBACK_TYPE(c_callback)
        self.lib.NetRedirector_SetConnectionCallback(self._conn_cb_ref)

    def add_proxy(self, ip, port, username="", password="", ptype=ProxyType.SOCKS5, name="MyProxy"):
        # Python 字符串需要編碼成 bytes (utf-8) 傳給 C
        return self.lib.NetRedirector_AddProxyConfig(
            ptype,
            name.encode('utf-8'),
            ip.encode('utf-8'),
            port,
            username.encode('utf-8'),
            password.encode('utf-8'),
            True # enabled
        )

    def add_rule(self, process_name, target_hosts="*", target_ports="*", protocol=RuleProtocol.BOTH, action=RuleAction.PROXY):
        return self.lib.NetRedirector_AddRule(
            process_name.encode('utf-8'),
            target_hosts.encode('utf-8'),
            target_ports.encode('utf-8'),
            protocol,
            action
        )

    # --- [新增] 高階統一入口:GUI 一律使用以下方法,不得直接呼叫 self.lib ---
    # 集中處理「PID vs 名稱規則」「協議字串轉換」「DLL 能力 fallback」,
    # 這些邏輯原本在 load_config / save_rule_action / reapply_all_rules 三處重複。

    @staticmethod
    def _protocol_from_str(proto_str):
        if proto_str == "TCP": return RuleProtocol.TCP
        if proto_str == "UDP": return RuleProtocol.UDP
        return RuleProtocol.BOTH

    def add_rule_ex(self, rule_type, target, hosts="*", ports="*", proto_str="BOTH", action=0, proxy_id=0):
        """新增規則 (統一入口)。rule_type: 'PID' 或 'Name'。回傳規則 ID,0 = 失敗。"""
        protocol = self._protocol_from_str(proto_str)
        if rule_type == 'PID':
            # [Fixed] isascii 檔掉全形數字 ('１２３') 與上標數字 ('²'):
            # str.isdigit() 對它們為 True, 但 int() 可能抛 ValueError
            t = str(target)
            if not (t.isascii() and t.isdigit()):
                return 0
            return self.add_rule_by_pid(int(t), hosts, ports, protocol, action, int(proxy_id))
        if self._has_add_rule_with_proxy:
            return self.lib.NetRedirector_AddRuleWithProxy(
                str(target).encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'),
                protocol, action, int(proxy_id))
        return self.add_rule(str(target), hosts, ports, protocol, action)

    def edit_rule_ex(self, rule_id, target, hosts="*", ports="*", proto_str="BOTH", action=0, proxy_id=0):
        """原地更新「名稱規則」(保留相同 ID)。回傳 True = 成功。
        PID 規則或舊版 DLL 不支援時回傳 False,呼叫端自行決定刪除重建。"""
        if not self._has_edit_rule_with_proxy or rule_id == 0:
            return False
        protocol = self._protocol_from_str(proto_str)
        return bool(self.lib.NetRedirector_EditRuleWithProxy(
            rule_id, str(target).encode('utf-8'), hosts.encode('utf-8'), ports.encode('utf-8'),
            protocol, action, int(proxy_id)))

    def delete_rule(self, rule_id):
        """刪除規則。回傳 True = 刪除成功;DLL 缺此匯出或刪除失敗回傳 False。"""
        if self._has_delete_rule:
            return bool(self.lib.NetRedirector_DeleteRule(rule_id))
        return False
    
    def set_default_proxy(self, ip, port, ptype=ProxyType.SOCKS5, username="", password=""):
        return self.lib.NetRedirector_SetProxyConfig(
            ptype,
            ip.encode('utf-8'),
            port,
            username.encode('utf-8'),
            password.encode('utf-8')
        )

    def start(self):
        print("[Python] Starting NetRedirector...")
        success = self.lib.NetRedirector_Start()
        if not success:
            print("[Python] Failed to start! (Check Admin privileges or missing drivers)")
        return success

    def stop(self):
        print("[Python] Stopping NetRedirector...")
        self.lib.NetRedirector_Stop()

# --- 使用範例 ---

def on_log_message(msg):
    print(f"[DLL Log] {msg}")

def on_new_connection(process, pid, ip, port, info):
    print(f"[Traffic] {process} ({pid}) -> {ip}:{port} [{info}]")

if __name__ == "__main__":
    # 檢查是否為管理員 (WinDivert 需要)
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except:
        is_admin = False

    if not is_admin:
        print("錯誤: 必須以「系統管理員」身分執行此腳本，因為需要加載 WinDivert 驅動。")
        sys.exit(1)

    # 初始化
    bridge = NetRedirectorWrapper("NetRedirector.dll")

    # 1. 設置回調
    bridge.set_log_callback(on_log_message)
    bridge.set_connection_callback(on_new_connection)

    # 2. 設置默認代理 (這裡請填寫你實際的代理服務器)
    # bridge.set_default_proxy("127.0.0.1", 10808, ProxyType.SOCKS5)

    # 3. 添加特定的代理配置
    proxy_id = bridge.add_proxy("127.0.0.1", 10808, username="", password="", name="LocalSocks")
    print(f"Added proxy with ID: {proxy_id}")

    # 4. 添加規則 (例如：讓 chrome.exe 通過代理)
    # Target Ports: "80;443" 或 "*"
    bridge.add_rule("chrome.exe", target_hosts="*", target_ports="*", action=RuleAction.PROXY)
    
    # 添加規則 (例如：讓 curl.exe 直連)
    bridge.add_rule("curl.exe", action=RuleAction.DIRECT)

    # 添加 PID 規則 (例如：讓 PID 為 1234 的進程通過代理)
    # bridge.add_rule_by_pid(1234, target_hosts="*", target_ports="*", action=RuleAction.PROXY)

    # 5. 啟動
    if bridge.start():
        print("NetRedirector is running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            bridge.stop()