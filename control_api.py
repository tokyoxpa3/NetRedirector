# -*- coding: utf-8 -*-
"""control_api.py — NetRedirector 本機控制 API (僅綁 127.0.0.1)。

為什麼需要它
    NetRedirector 以 WinDivert 攔截封包，常把未特別指定的流量導向代理。
    同一台機器上由我們自己維護的工具 (例如 MultiSocksDownloader) 必須
    「直連」才能自行掌握它通往各 SOCKS5 代理的連線；否則它發出的代理連線
    會被 NetRedirector 再轉一次，多代理聚合就會失效。這個 API 讓那些工具
    在啟動時查詢「我是否已被設為直連」，沒有就請 NetRedirector 補一條
    DIRECT 規則。

為什麼是本機 HTTP 而非具名管道 (named pipe)
    NetRedirector 必須以系統管理員身分執行 (WinDivert 驅動)，呼叫端卻通常
    是一般使用者權限。Windows 具名管道受完整性等級 (IL) ACL 限制，管理員
    行程開的管道，一般權限行程常被拒絕；loopback TCP 不受此限制。

為什麼要 token
    只綁 127.0.0.1 已擋掉遠端來源，但同機的其他行程仍可連進來改規則。
    因此以一個共享 token (存於使用者家目錄) 驗證身分；呼叫端讀同一個
    檔案即可取得 token。token 為空字串時不檢查 (供測試)。

端點
    GET  /ping                            回傳版本與執行狀態
    GET  /rules[?target=NAME]             查詢規則 (可依進程名過濾)
    POST /ensure-direct {"target": "x"}   確保該進程名有啟用中的 DIRECT 規則
    (請求需帶 X-NR-Token 標頭)
"""

import json
import logging
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

DEFAULT_HOST = "127.0.0.1"

# 控制 API 連接埠。NetRedirector 的 Hub 使用 30677-30692，MultiSocksDownloader
# 使用 8765/8766，故此處選 8767 避開已知佔用。
DEFAULT_PORT = 8767

# NetRedirector 啟動時要主動照顧的自家程式 (可由設定檔 auto_direct 覆寫)。
# 這些程式自行掌握代理連線，被 NetRedirector 再轉一次就會失效。
DEFAULT_AUTO_DIRECT = ["MultiSocksDownloader.exe"]

# 通用直譯器名稱：對它們設直連會讓「所有」同直譯器程式一起直連 —— 例如
# python.exe 直連會連 NetRedirector 自己 (同樣是 Python 執行) 都被直連，
# 導致攔截失效。這幾乎必然是誤用 (開發模式跑原始碼時進程名就是 python.exe)，
# 因此一律拒絕，要求呼叫端改用 PID 規則。
_GENERIC_INTERPRETER_RE = re.compile(
    r"^(python|pythonw|py)(\d+(\.\d+)*)?\.exe$", re.IGNORECASE)


def is_generic_interpreter(name):
    """判斷進程名是否為通用直譯器 (python.exe / pythonw.exe / py.exe 等)。

    這類名稱代表「一大群互不相關的程式」，對它們設直連會波及整個系統，
    不是有效的直連設定。
    """
    return bool(_GENERIC_INTERPRETER_RE.match((name or "").strip()))


# 共享 token 檔案位置。放在使用者家目錄而非程式目錄：程式可能安裝在
# 無寫入權限的位置 (例如 Program Files)，家目錄則穩定可寫。
TOKEN_DIR = os.path.join(os.path.expanduser("~"), ".netredirector")
TOKEN_FILE = os.path.join(TOKEN_DIR, "control.token")


def load_or_create_token(path=TOKEN_FILE):
    """讀取共享 token；不存在或為空時生成一個並寫入。

    寫入失敗 (權限/防毒鎖檔) 時仍回傳生成的 token，只是本次啟動的呼叫端
    會因讀不到檔案而驗證失敗 —— 這種情況記一筆警告即可，不應讓 API 起不來。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            token = f.read().strip()
        if token:
            return token
    except OSError:
        pass

    token = secrets.token_hex(24)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(token)
    except OSError as e:
        logger.warning("無法寫入控制 token (%s): %s", path, e)
    return token


class _ControlHandler(BaseHTTPRequestHandler):
    # 用 HTTP/1.0：每個請求一條連線、回應後即關閉，省去 keep-alive 的
    # 半開連線管理。本 API 呼叫頻率極低 (程式啟動時一次)，不值得為此複雜化。
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        return  # 靜音：預設會把每個請求印到 stderr，對常駐服務太吵

    def _send_json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self):
        token = getattr(self.server, "token", None)
        if not token:
            return True
        return self.headers.get("X-NR-Token", "") == token

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def do_GET(self):
        try:
            if not self._authorized():
                return self._send_json(401, {"error": "unauthorized"})
            parsed = urlparse(self.path)
            if parsed.path == "/ping":
                return self._send_json(
                    200, self.server.dispatch(self.server.ping_fn))
            if parsed.path == "/rules":
                target = (parse_qs(parsed.query).get("target") or [None])[0]
                rules = self.server.dispatch(
                    lambda: self.server.list_rules_fn(target))
                return self._send_json(200, {"rules": rules})
            return self._send_json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001 — 任何後端錯誤都不該讓連線裸斷
            logger.exception("control API GET 失敗")
            return self._send_json(500, {"error": str(e)})

    def do_POST(self):
        try:
            if not self._authorized():
                return self._send_json(401, {"error": "unauthorized"})
            parsed = urlparse(self.path)
            if parsed.path == "/ensure-direct":
                data = self._read_json()
                if data is None:
                    return self._send_json(400, {"error": "invalid json"})
                target = str(data.get("target") or "").strip()
                if not target:
                    return self._send_json(400, {"error": "missing target"})
                result = self.server.dispatch(
                    lambda: self.server.ensure_direct_fn(target))
                return self._send_json(200, result)
            return self._send_json(404, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            logger.exception("control API POST 失敗")
            return self._send_json(500, {"error": str(e)})


class ControlApiServer:
    """把本機控制 API 跑在背景執行緒。

    規則的讀寫都在 UI 執行緒 (Qt 物件與 DLL 呼叫皆非執行緒安全)，因此
    實際操作一律透過 ``dispatch`` 轉送；``dispatch(fn)`` 需在 UI 執行緒
    執行 ``fn`` 並回傳其結果。測試時可傳 ``lambda fn: fn()`` 同步執行。

    參數
        dispatch          callable(fn) -> fn 的結果 (跨執行緒轉送)
        ping_fn           () -> dict
        list_rules_fn     (target|None) -> list[dict]
        ensure_direct_fn  (target) -> dict
        token             共享 token；空字串/None 表示不驗證
    """

    def __init__(self, dispatch, ping_fn, list_rules_fn, ensure_direct_fn,
                 host=DEFAULT_HOST, port=DEFAULT_PORT, token=None):
        self._dispatch = dispatch
        self._ping_fn = ping_fn
        self._list_rules_fn = list_rules_fn
        self._ensure_direct_fn = ensure_direct_fn
        self.host = host
        self.port = port
        self.token = token
        self._httpd = None
        self._thread = None

    @property
    def actual_port(self):
        """實際綁定的埠 (port=0 時由系統指派，測試用)。"""
        if self._httpd is not None:
            return self._httpd.server_address[1]
        return self.port

    def start(self):
        """啟動 API；回傳是否成功。

        埠被占用或綁定失敗時回傳 False，呼叫端只需記錄一筆訊息，不應
        因此讓主程式起不來 —— 控制 API 只是加分功能。
        """
        try:
            httpd = ThreadingHTTPServer(
                (self.host, self.port), _ControlHandler)
        except OSError as e:
            logger.warning("控制 API 啟動失敗 (%s:%s): %s", self.host, self.port, e)
            return False

        httpd.daemon_threads = True
        httpd.dispatch = self._dispatch
        httpd.ping_fn = self._ping_fn
        httpd.list_rules_fn = self._list_rules_fn
        httpd.ensure_direct_fn = self._ensure_direct_fn
        httpd.token = self.token
        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, name="NRControlApi", daemon=True)
        self._thread.start()
        logger.info("控制 API 已啟動: http://%s:%s", self.host, self.actual_port)
        return True

    def stop(self):
        """停止 API 並釋放埠。可重複呼叫。"""
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:  # noqa: BLE001 — 關閉失敗不該阻擋主程式退出
                logger.exception("控制 API 關閉時發生錯誤")
            self._httpd = None
        self._thread = None
