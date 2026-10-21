import sys
import time
import threading
import logging
import ctypes
import os

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem, 
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit, 
                             QListWidget, QSplitter, QMessageBox, QHeaderView,
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu,
                             QSystemTrayIcon, QCheckBox, QFrame, QWidgetAction,
                             QProgressDialog)
from PySide6.QtCore import Qt, Signal, QTimer, QEvent, QThread, QPoint, QObject
from PySide6.QtGui import QColor, QBrush, QAction, QIcon

from i18n import i18n as tr, SUPPORTED_LANGS

from app_icon import get_app_icon
import single_instance
import startup  # [開機自動啟動] Windows 工作排程器登錄
import ui_theme  # [現代化 UI] 深色主題 QSS / QPalette / 徽章輔助

# 匯入現有的模組
import network_utils
import proxy_core
import secure_config  # [新增] 密碼 DPAPI 加密儲存
import rule_utils  # [模組化] 規則欄位處理 (全形星號正規化等)
import config_store  # [模組化] 設定序列化與檔案 I/O
import process_utils  # [本機控制 API] 列舉執行中進程，供 auto_direct 啟動掃描
import control_api  # [本機控制 API] 讓自家工具查詢/請求直連規則
from autosave import SaveScheduler  # [自動存檔] 變更即存 + 關機前強制落地
import interface_metrics  # [介面計量] SoftEther 虛擬網卡 vs 實體網卡計量校正
from app_helpers import (  # [模組化] GUI 輔助元件 (自本檔抽出)
    check_proxy_connection, SignalLogHandler, NetworkMonitorWorker, RedirectorSignals,
)
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol
from tabs_hub import HubTabMixin
from tabs_rules import RulesTabMixin
from tabs_proxies import ProxiesTabMixin
from tabs_monitor import MonitorTabMixin
from tabs_vpngate import VpnGateTabMixin

import updater  # [自動更新] 檢查/下載/替換邏輯
from version import APP_VERSION  # [自動更新] 單一版本來源


def _fmt_bytes(n):
    """把位元組數格式化成易讀字串 (更新進度顯示用)。"""
    value = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return ("{:.0f} {}" if unit == "B" else "{:.1f} {}").format(value, unit)
        value /= 1024
    return "{:.1f} TB".format(value)


class UiDispatch(QObject):
    """把背景執行緒的呼叫排回 UI 執行緒執行 (本機控制 API 用)。

    規則的讀寫都必須在 UI 執行緒 (Qt 物件與 DLL 呼叫皆非執行緒安全)，而
    控制 API 的請求由背景執行緒處理，因此需要這條跨執行緒通道：emit 之後
    由 receiver 所在執行緒 (UI) 執行實際動作。
    """
    run = Signal(object)  # 傳入 callable，於 UI 執行緒執行


class UpdateWorker(QThread):
    """背景檢查更新 (呼叫 GitHub API，避免阻塞 UI)。"""
    result = Signal(object)  # dict(有更新) | None(最新) | Exception(錯誤)

    def __init__(self, current_version):
        super().__init__()
        self.current_version = current_version

    def run(self):
        try:
            self.result.emit(updater.check_update(self.current_version))
        except Exception as e:  # noqa: BLE001 — 網路錯誤需回報 UI
            self.result.emit(e)


class StageWorker(QThread):
    """背景下載並驗證更新 (回傳新版本目錄路徑)。"""
    result = Signal(object)    # str(new_dir) | Exception
    progress = Signal(object)  # dict(downloaded, total, speed, threads)
    log = Signal(str)          # 選路/換線等文字訊息

    def __init__(self, info):
        super().__init__()
        self.info = info
        self._cancel_event = threading.Event()

    def cancel(self):
        """要求中止下載 (由 UI 的取消鈕呼叫)。"""
        self._cancel_event.set()

    def run(self):
        try:
            path = updater.stage_update(
                self.info["url"], self.info["asset_name"], self.info["checksum_url"],
                progress_cb=self.progress.emit, cancel_event=self._cancel_event,
                log_cb=self.log.emit)
            self.result.emit(path)
        except Exception as e:
            self.result.emit(e)


class MainWindow(QMainWindow, HubTabMixin, RulesTabMixin, ProxiesTabMixin, MonitorTabMixin, VpnGateTabMixin):
    update_proxy_table_signal = Signal() 
    metric_sync_done = Signal(object)  # 背景校正介面計量的結果 (dict)
    CONFIG_FILE = "config.json"  # [新增] 設定檔路徑

    def __init__(self):
        super().__init__()
        self._i18n_registry = []
        self._set_window_title()
        self.resize(1024, 768)

        # 應用程式圖示 (工作列/視窗/tray 共用)
        self._app_icon = get_app_icon()
        self.setWindowIcon(self._app_icon)

        # 系統匣與關閉行為狀態
        self._really_quit = False      # True 時關閉即真正離開程式
        self._tray_notified = False    # 是否已顯示過「縮到匣」提示
        self._tray_icon = None         # QSystemTrayIcon 實例 (延後於 setup_ui 後建立)

        # [自動存檔] 設定變更後延遲寫檔。scheduler 於 setup_ui 之後才建立，
        # 因此 UI 初始化期間 (勾選框預設值) 的訊號不會提前寫入設定檔。
        self._save_scheduler = None
        self._loading_config = False   # True 時不排程存檔 (見 load_config)
        self._shutdown_done = False    # 關閉流程已開始，不再排程新的存檔

        # 自動更新狀態
        self.check_updates_on_start = True
        self.update_worker = None
        self.stage_worker = None
        self._update_checked = False

        dll_path = "NetRedirector.dll"
        
        try:
            self.bridge = NetRedirectorWrapper(dll_path)
        except Exception as e:
            # 依錯誤型別提供更精準的提示 (FileNotFoundError 是 OSError 子類，需先判斷)
            if isinstance(e, FileNotFoundError):
                detail = tr.t("找不到 NetRedirector.dll")
            elif isinstance(e, OSError):
                detail = tr.t("載入 DLL 失敗，可能缺少 WinDivert.dll 或 vcruntime140.dll")
            else:
                detail = str(e)
            QMessageBox.critical(
                None, tr.t("初始化失敗"),
                tr.t("無法載入 NetRedirector.dll：{detail}\n\n請確認：\n"
                     "1. NetRedirector.dll、WinDivert.dll、WinDivert64.sys 在同目錄\n"
                     "2. 以系統管理員身分執行").format(detail=detail)
            )
            logging.exception("Failed to load NetRedirector DLL")
            sys.exit(1)

        # 核心數據結構
        self.port_config = {}      # Hub: { port: [interface_names] }
        self.hub_proxy_map = {}    # Hub Port -> Proxy ID
        self.custom_proxies = []   # List of dict: Manual Proxies
        self.rules = []            # Rules list
        # [本機控制 API] 啟動時要主動確保為直連的自家程式進程名清單；
        # 舊設定檔無此欄位時於還原階段帶入預設值 (見 _apply_loaded_config)
        self.auto_direct = list(control_api.DEFAULT_AUTO_DIRECT)
        # 齒輪選單的「自動偵測並加入直連程式」開關；關閉則啟動掃描不執行
        self.auto_direct_enabled = True
        self.control_api = None    # 本機控制 API server (於 __init__ 尾端啟動)
        self.current_interfaces = {}
        self.selected_hub_port = None
        self.is_redirector_running = False

        # 設置 Redirector 回調
        self.redir_signals = RedirectorSignals()
        self.redir_signals.log_received.connect(self.on_dll_log)
        self.redir_signals.traffic_received.connect(self.on_traffic_event)
        
        self.bridge.set_log_callback(self.redir_signals.log_received.emit)
        self.bridge.set_connection_callback(self.redir_signals.traffic_received.emit)

        # [新增] 可配置的 Ping 目標 (需在 setup_ui 之前初始化，UI 會引用)
        self.ping_target = network_utils.PING_TARGET

        # UI 初始化
        self.setup_ui()

        # [自動存檔] 設定變更後延遲寫入 config.json；關機/登出時強制落地。
        # Windows 關機時 Qt 會在 WM_QUERYENDSESSION 發出 commitDataRequest，
        # 程序隨後就被終止 —— 沒有接這個訊號，最後的變更一定會消失。
        self._save_scheduler = SaveScheduler(self._auto_save, parent=self)
        app = QApplication.instance()
        if app is not None:
            app.commitDataRequest.connect(self._on_commit_data_request)
            app.aboutToQuit.connect(self._on_about_to_quit)

        # 右上角「⚙」溢出選單 (設定 + 檢查更新 / 關於；不再使用獨立選單列)
        self._setup_overflow_menu()

        # 系統匣 (需在 setup_ui 之後，chkbox 已存在；且需有 QApplication)
        self._setup_tray()

        # 啟動網路監控
        self.monitor_thread = NetworkMonitorWorker(self.ping_target)
        self.monitor_thread.data_updated.connect(self.on_network_update)
        self.monitor_thread.start()

        # 依當前分頁啟用/停用延遲 ping (僅 Hub 分頁需要)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.on_tab_changed(self.tabs.currentIndex())
        
        # Log Handler
        self.log_handler = SignalLogHandler()
        self.log_handler.setFormatter(logging.Formatter('%(asctime)s - [Hub] %(message)s', datefmt='%H:%M:%S'))
        self.log_handler.log_signal.connect(self.append_log)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.INFO)

        self.update_proxy_table_signal.connect(self.refresh_custom_proxy_table)
        self.metric_sync_done.connect(self._on_metric_sync_done)

        # [本機控制 API] 跨執行緒把請求排回 UI 執行緒 (規則讀寫必須在此)。
        # 連線必須在 API server 啟動前建立，否則第一筆請求可能落空。
        self._ui_dispatch = UiDispatch()
        self._ui_dispatch.run.connect(self._run_on_ui)

        # [本機控制 API] 只綁 127.0.0.1，供自家工具查詢/請求直連規則。
        # 埠被占用時 start() 回 False，只記一筆訊息，不影響主程式。
        self.control_api = control_api.ControlApiServer(
            dispatch=self._call_on_ui,
            ping_fn=self._api_ping,
            list_rules_fn=self._api_list_rules,
            ensure_direct_fn=self._api_ensure_direct,
            token=control_api.load_or_create_token(),
        )
        if self.control_api.start():
            self.append_log(
                f"本機控制 API 已啟動 (127.0.0.1:{self.control_api.actual_port})")

        # [新增] 載入設定
        QTimer.singleShot(100, self.load_config)

        # [自動更新] 啟動時背景檢查 (延後至設定載入完成後，依設定決定是否執行)
        QTimer.singleShot(1200, self._on_startup_update_check)

        self.append_log("系統就緒。")

    # --- 多國語系支援 ---
    def t(self, s):
        return tr.t(s)

    def _set_window_title(self):
        self.setWindowTitle(f"{self.t('NetRedirector x GameProxyHub 整合專業版')} v{APP_VERSION}")

    def _reg(self, kind, *args):
        self._i18n_registry.append((kind, args))
        self._apply_i18n(kind, args)

    def _apply_i18n(self, kind, args):
        if kind == "text":
            args[0].setText(self.t(args[1]))
        elif kind == "title":
            args[0].setTitle(self.t(args[1]))
        elif kind == "placeholder":
            args[0].setPlaceholderText(self.t(args[1]))
        elif kind == "combo":
            combo, keys = args
            idx = combo.currentIndex()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems([self.t(k) for k in keys])
            if idx >= 0 and idx < len(keys):
                combo.setCurrentIndex(idx)
            combo.blockSignals(False)
            # [Fixed] QComboBox 預設 (AdjustToContentsOnFirstShow) 僅在首次顯示時
            # 量測寬度，切換語言後較長的譯文會超出而被裁掉 (例: ru "BLOCK
            # (блокировать)")。改為每次重填後依最長項目重算寬度，並以最小寬度
            # 鎖住，避免版面重排時又被壓回原尺寸。
            combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
            combo.updateGeometry()
            combo.setMinimumWidth(combo.sizeHint().width())
        elif kind == "headers":
            tbl, keys = args
            tbl.setHorizontalHeaderLabels([self.t(k) for k in keys])
        elif kind == "tab":
            args[0].setTabText(args[1], self.t(args[2]))
        elif kind == "window":
            args[0].setWindowTitle(self.t(args[1]))
        elif kind == "tooltip":
            args[0].setToolTip(self.t(args[1]))

    def retranslate_ui(self):
        for kind, args in self._i18n_registry:
            self._apply_i18n(kind, args)
        self._set_window_title()
        self.update_service_status()
        self.update_hub_status()
        self.refresh_proxy_combobox()
        self.refresh_rules_table()
        self.refresh_custom_proxy_table()
        self.refresh_hub_table()
        # [即時監控] 暫停鈕文字與計數徽章不在 _i18n_registry 內，需手動重刷
        if hasattr(self, 'btn_traffic_pause'):
            self._sync_traffic_pause_text()
            self._refresh_traffic_counters()
        idx = self.combo_lang.findData(tr.lang)
        if idx >= 0 and idx != self.combo_lang.currentIndex():
            self.combo_lang.blockSignals(True)
            self.combo_lang.setCurrentIndex(idx)
            self.combo_lang.blockSignals(False)

    def on_lang_changed(self, idx):
        code = self.combo_lang.itemData(idx)
        if code and code != tr.lang:
            tr.load(code)
            self.retranslate_ui()
            self.append_log(f"語言已切換: {tr.lang_name(code)}")
            self._request_save()

    # [新增] Ping 目標變更 (即時套用至監控執行緒，並於下次存檔時寫入 config.json)
    def on_ping_target_changed(self):
        target = self.ent_ping_target.text().strip()
        if not target:
            target = network_utils.PING_TARGET
            self.ent_ping_target.setText(target)
        if target != self.ping_target:
            self.ping_target = target
            self.monitor_thread.set_ping_target(target)
            self.append_log(f"Ping 目標已更新: {target}")
            self._request_save()

    def on_tab_changed(self, index):
        # 只有 Hub 分頁需要即時介面延遲顯示；其餘分頁停用延遲 ping，
        # 但網卡掃描與路由同步仍持續進行 (見 NetworkMonitorWorker.run)
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.set_ping_enabled(index == 0)

    def update_service_status(self):
        running = self.is_redirector_running
        self.btn_master_switch.setText(
            "⏹ " + self.t("停止") if running else "▶ " + self.t("啟動"))
        ui_theme.set_button_kind(self.btn_master_switch, "DangerBtn" if running else "SuccessBtn")
        self.lbl_status.setText(
            "● " + (self.t("攔截狀態: 運行中") if running else self.t("攔截狀態: 停止")))
        ui_theme.style_badge(
            self.lbl_status, ui_theme.COLOR_SUCCESS if running else ui_theme.COLOR_DANGER)
        self.update_dashboard_badges()

    def update_dashboard_badges(self):
        """更新頂部儀表徽章：核心延遲與活動轉發數。"""
        # 核心延遲：取所有已連線介面中最低的延遲值
        latency = None
        for data in self.current_interfaces.values():
            if not data.get('connected'):
                continue
            value = data.get('latency')
            if value is None or value >= 9000:
                continue
            latency = value if latency is None else min(latency, value)
        if latency is None:
            self.lbl_ping_badge.setText(f"⚡ {self.t('核心延遲:')} --")
            ui_theme.style_badge(self.lbl_ping_badge, "#64748B")
        else:
            self.lbl_ping_badge.setText(f"⚡ {self.t('核心延遲:')} {latency} ms")
            ui_theme.style_badge(self.lbl_ping_badge, ui_theme.COLOR_ACCENT)

        total = sum(
            int(info.get('active_conns', 0))
            for info in proxy_core.route_manager.interfaces.values())
        self.lbl_conns_badge.setText(f"🌐 {self.t('活動轉發:')} {total}")
        ui_theme.style_badge(self.lbl_conns_badge, ui_theme.COLOR_WARN)

    def update_hub_status(self):
        if self.selected_hub_port:
            self.lbl_hub_status.setText(self.t("當前端口: {port}").format(port=self.selected_hub_port))
        else:
            self.lbl_hub_status.setText(self.t("未選擇端口"))

    # --------------------------------------------------------- 設定自動存檔
    def _request_save(self, delay_ms=None):
        """請求延遲存檔 (覆寫 AutoSaveMixin 版本以避開設定載入期)。"""
        if self._loading_config or self._shutdown_done:
            return
        super()._request_save(delay_ms)

    def _auto_save(self):
        """延遲存檔計時器到期：安靜寫入 (不洗日誌)。"""
        self.save_config(quiet=True)

    def _on_commit_data_request(self, manager=None):
        """Windows 關機/登出：強制把設定寫進磁碟。

        Qt 在 WM_QUERYENDSESSION 會發出 commitDataRequest (見
        qwindowscontext.cpp / QGuiApplicationPrivate::commitData)，程序隨後
        就被終止，所以這裡必須「同步」寫檔，不能只排程。
        """
        self._flush_save(force=True)

    def _on_about_to_quit(self):
        """事件迴圈結束前，補寫尚未落地的變更。"""
        self._flush_save()

    def _flush_save(self, force=False):
        """立刻寫檔；force=True 時即使沒有待寫變更也寫一次。"""
        if self._save_scheduler is not None:
            self._save_scheduler.flush(force=force)

    def on_pref_toggled(self, _checked=False):
        """偏好勾選項變更：排程寫入設定 (autostart 另有即時存檔)。"""
        self._request_save()

    # --------------------------------------------------------- 本機控制 API
    def _run_on_ui(self, fn):
        """UiDispatch.run 的接收端：在 UI 執行緒執行 fn。"""
        fn()

    def _call_on_ui(self, fn, timeout=5.0):
        """在 UI 執行緒執行 fn 並等待結果 (供控制 API 的背景執行緒呼叫)。

        規則讀寫與 DLL 呼叫都必須在 UI 執行緒，故以 signal 排入：emit 在
        背景執行緒、receiver 在 UI 執行緒，Qt 會自動以 queued 方式投遞。
        """
        if QThread.currentThread() is self.thread():
            return fn()  # 已在 UI 執行緒，直接執行，省去往返

        box = {}
        done = threading.Event()

        def wrapper():
            try:
                box['value'] = fn()
            except Exception as e:  # noqa: BLE001 — 原樣轉回呼叫端處理
                box['error'] = e
            finally:
                done.set()

        self._ui_dispatch.run.emit(wrapper)
        if not done.wait(timeout):
            raise TimeoutError("UI 執行緒無回應")
        if 'error' in box:
            raise box['error']
        return box.get('value')

    def _api_ping(self):
        """GET /ping：回傳版本與執行狀態。"""
        return {
            "app": "NetRedirector",
            "version": APP_VERSION,
            "pid": os.getpid(),
            "running": bool(self.is_redirector_running),
        }

    def _api_list_rules(self, target=None):
        """GET /rules：列出規則 (可依進程名過濾)。"""
        want = (target or "").strip().lower()
        result = []
        for r in self.rules:
            if want and str(r.get('target', '')).lower() != want:
                continue
            result.append({
                "id": int(r.get('id') or 0),
                "enabled": bool(r.get('enabled', True)),
                "type": r.get('type', 'Name'),
                "target": r.get('target', ''),
                "hosts": r.get('hosts', '*'),
                "ports": r.get('ports', '*'),
                "proto": r.get('proto', 'BOTH'),
                "action_key": self._rule_action_idx(r),
                "auto": bool(r.get('auto', False)),
            })
        return result

    def _has_enabled_direct_rule(self, target):
        """回傳指向 target 且啟用中的 DIRECT 名稱規則；沒有則回 None。"""
        want = target.lower()
        for r in self.rules:
            if (r.get('enabled', True)
                    and r.get('type') == 'Name'
                    and str(r.get('target', '')).lower() == want
                    and self._rule_action_idx(r) == 1):
                return r
        return None

    def _add_auto_direct_rule(self, target):
        """新增一條自動直連規則。呼叫端須先確認尚無同名規則。

        回傳新增的 rule dict；DLL 拒絕時回 None。
        """
        rid = self.bridge.add_rule_ex('Name', target, '*', '*', 'BOTH', 1, 0)
        if rid <= 0:
            self.append_log(f"自動直連規則新增失敗 (目標: {target})")
            return None
        rule = {
            'id': int(rid),
            'enabled': True,
            'type': 'Name',
            'target': target,
            'hosts': '*',
            'ports': '*',
            'proto': 'BOTH',
            'action': self.t("DIRECT (直連)"),
            'action_key': 1,
            'proxy': self.t("未指定 (Fallback to Direct)"),
            'proxy_name': '',
            'proxy_id': 0,
            'auto': True,
        }
        self.rules.append(rule)
        return rule

    def _remember_auto_direct(self, target):
        """把 target 記進 auto_direct 清單 (不分大小寫去重)，讓下次啟動也照顧。"""
        if target.lower() not in [t.lower() for t in self.auto_direct]:
            self.auto_direct.append(target)

    def _api_ensure_direct(self, target):
        """POST /ensure-direct：確保 target 有啟用中的 DIRECT 規則。

        冪等：已有啟用中的 DIRECT 名稱規則就直接回報，不重複新增 ——
        C 核心的 AddRule 不去重，重複呼叫會堆出多條相同規則。
        """
        target = (target or "").strip()
        if not target:
            return {"added": False, "error": "missing target"}
        if control_api.is_generic_interpreter(target):
            # 通用直譯器 (python.exe 等) 直連會波及所有同類程式，包含 NR 自己。
            # 仍允許 (呼叫端可能刻意如此，例如開發模式跑原始碼)，只記一筆提示。
            self.append_log(
                f"注意：{target} 為通用直譯器名稱，設為直連會讓所有 Python "
                f"程式一起直連")

        existing = self._has_enabled_direct_rule(target)
        if existing is not None:
            self._remember_auto_direct(target)
            self._request_save()
            return {"added": False, "existed": True,
                    "rule_id": int(existing.get('id') or 0)}

        rule = self._add_auto_direct_rule(target)
        if rule is None:
            return {"added": False, "error": "driver rejected rule"}

        self._remember_auto_direct(target)
        self.refresh_rules_table()
        self._request_save()
        self.append_log(f"已自動為 {target} 加入直連規則 (ID: {rule['id']})")
        return {"added": True, "existed": False, "rule_id": rule['id']}

    def _scan_auto_direct_targets(self):
        """啟動後掃描一次 auto_direct：為正在執行、且尚無任何規則的目標進程
        補上直連規則。

        只在「該進程正在執行」且「使用者尚未為它建立任何規則 (含停用)」時
        才動作。後者是為了尊重使用者的停用/自訂意圖，避免每次啟動都把被
        停用的規則又加回來。
        """
        if not self.auto_direct or not self.auto_direct_enabled:
            return
        try:
            running = {n.lower() for n in process_utils.list_process_names()}
        except Exception:  # noqa: BLE001 — 列舉失敗只代表這次不掃，不影響主流程
            return
        existing = {str(r.get('target', '')).lower() for r in self.rules}
        added = False
        for target in list(self.auto_direct):
            key = target.lower()
            if key not in running or key in existing:
                continue
            if control_api.is_generic_interpreter(target):
                # 使用者若把 python.exe 之類放進清單，仍照做，只提示副作用
                self.append_log(
                    f"注意：{target} 為通用直譯器名稱，設為直連會讓所有 Python "
                    f"程式一起直連")
            rule = self._add_auto_direct_rule(target)
            if rule is not None:
                added = True
                self.append_log(
                    f"偵測到 {target} 正在執行，已自動加入直連規則 (ID: {rule['id']})")
        if added:
            self.refresh_rules_table()
            self._request_save()

    def on_auto_direct_toggled(self, checked):
        """齒輪選單的「自動偵測並加入直連程式」開關。

        關閉：啟動掃描不再執行。開啟：把預設清單的項目補回並立即掃描一次
        —— 這是使用者刪除自動規則後，讓自動偵測回來的入口。
        """
        self.auto_direct_enabled = bool(checked)
        if checked:
            for name in control_api.DEFAULT_AUTO_DIRECT:
                self._remember_auto_direct(name)
            self._scan_auto_direct_targets()
        self._request_save()

    # [模組化] 儲存設定 (序列化/檔案 I/O 移至 config_store)
    def save_config(self, quiet=False):
        """把目前狀態寫入 config.json。

        quiet=True 用於自動存檔 (變更即存)，不寫「設定已儲存」日誌以免洗版；
        寫入失敗一律記錄，因為那代表使用者的設定沒有落地。
        """
        data = config_store.build_config_data(
            tr.lang, self.ping_target,
            self.chk_minimize_to_tray.isChecked() if hasattr(self, 'chk_minimize_to_tray') else False,
            self.port_config, self.custom_proxies, self.rules,
            self.chk_check_updates.isChecked() if hasattr(self, 'chk_check_updates') else True,
            self.chk_autostart.isChecked() if hasattr(self, 'chk_autostart') else True,
            (self.chk_manage_metric.isChecked()
             if hasattr(self, 'chk_manage_metric') else True),
            self.auto_direct, self.auto_direct_enabled)
        err = config_store.save_config_file(self.CONFIG_FILE, data)
        if err is None:
            if not quiet:
                self.append_log("設定已儲存至 config.json")
        else:
            self.append_log(f"儲存設定失敗: {err}")

    # [模組化] 讀取設定 (檔案 I/O 移至 config_store)
    def load_config(self):
        """載入設定檔；載入期間暫停自動存檔排程。

        還原勾選框會發出 toggled 訊號，若不暫停，剛讀到的設定會被立刻再寫
        回去；還原中途失敗時更會把「半套」狀態覆寫成正式設定檔。
        """
        self._loading_config = True
        try:
            self._apply_loaded_config()
        finally:
            self._loading_config = False
        # [本機控制 API] 設定載入完成後掃描一次 auto_direct：當 NR 比目標
        # 程式晚啟動時，靠這一步補上直連規則 (目標程式較晚啟動時，則由它
        # 自己呼叫 API 請求，兩者互補即可涵蓋誰先誰後，且不需持續輪詢)。
        QTimer.singleShot(0, self._scan_auto_direct_targets)

    def _apply_loaded_config(self):
        # [Fixed] 先記錄檔案是否存在: 讀取前存在但解析失敗 → 這次真的氈損
        # (已被改名為 .bak);檔案本來就不存在但殘留舊 .bak → 不誤發警告
        had_file = os.path.exists(self.CONFIG_FILE)
        data = config_store.load_config_file(self.CONFIG_FILE)
        if data is None:
            if had_file:
                self.append_log(
                    "警告: config.json 毀損無法解析,原始內容已備份為 config.json.corrupt.bak,"
                    "可手動修復後還原。本次以空白設定啟動。")
            # 沒有設定檔 (首次啟動) 或無法讀取時，開機自動啟動仍預設開啟
            self._apply_autostart(True)
            self._sync_interface_metrics()
            return

        try:
            saved_lang = data.get("lang")
            if saved_lang:
                tr.load(saved_lang)

            # [新增] 還原 Ping 目標 (若設定檔未提供則使用預設)
            saved_ping = data.get("ping_target", "")
            if saved_ping:
                self.ping_target = saved_ping
                self.monitor_thread.set_ping_target(saved_ping)
                if hasattr(self, 'ent_ping_target'):
                    self.ent_ping_target.setText(saved_ping)

            # [本機控制 API] 還原 auto_direct。舊設定檔沒有此欄位 (None) 時
            # 保留預設清單；明確的空清單代表使用者已清空，須原樣採用。
            saved_auto_direct = data.get("auto_direct")
            if saved_auto_direct is not None:
                self.auto_direct = [
                    str(t).strip() for t in saved_auto_direct
                    if str(t).strip()]
            self.auto_direct_enabled = bool(
                data.get("auto_direct_enabled", True))
            if hasattr(self, "chk_auto_direct"):
                # blockSignals：還原狀態不該觸發 on_auto_direct_toggled 而掃描
                self.chk_auto_direct.blockSignals(True)
                self.chk_auto_direct.setChecked(self.auto_direct_enabled)
                self.chk_auto_direct.blockSignals(False)

            # 還原「關閉時縮到系統匣」
            if hasattr(self, 'chk_minimize_to_tray'):
                self.chk_minimize_to_tray.setChecked(bool(data.get("minimize_to_tray", False)))

            # 還原「啟動時自動檢查更新」
            self.check_updates_on_start = bool(data.get("check_updates", True))
            if hasattr(self, 'chk_check_updates'):
                self.chk_check_updates.setChecked(self.check_updates_on_start)

            # 還原「開機時自動啟動」(舊設定檔無此欄位時預設開啟)
            self._apply_autostart(bool(data.get("autostart", True)))

            # 還原「自動管理介面計量」(舊設定檔無此欄位時預設開啟)，並立即校正。
            # 首次建立 SoftEther 虛擬網卡的使用者不需要再手動設定計量。
            if hasattr(self, 'chk_manage_metric'):
                self.chk_manage_metric.setChecked(bool(data.get("manage_metric", True)))
            self._sync_interface_metrics()

            self.append_log("正在還原設定...")

            # 1. 還原 Custom Proxies
            saved_proxies = data.get("proxies", [])
            for p in saved_proxies:
                ptype = ProxyType.SOCKS5 if p['type'] == "SOCKS5" else ProxyType.HTTP
                plain_pass = secure_config.decrypt_password(p.get('pass', ''))  # [新增] 解密儲存的密碼
                pid = self.bridge.add_proxy(p['ip'], int(p['port']), p['user'], plain_pass, ptype, p['name'])
                if pid > 0:
                    send_domain = bool(p.get('send_domain', False))
                    self.bridge.set_proxy_send_domain(pid, send_domain)
                    self.custom_proxies.append({
                        'id': pid, # 取得新的 ID
                        'name': p['name'],
                        'type': p['type'],
                        'ip': p['ip'],
                        'port': p['port'],
                        'user': p['user'],
                        'pass': plain_pass,
                        'latency': '-',
                        'send_domain': send_domain
                    })
            self.refresh_custom_proxy_table()

            # 2. 還原 Hubs
            saved_hubs = data.get("hubs", {})
            for port_str, interfaces in saved_hubs.items():
                port = int(port_str)
                self.port_config[port] = interfaces
                self.list_hub_ports.addItem(f"{port}")

                # 自動啟動 Hub
                proxy_core.route_manager.update_port_binding(port, interfaces)
                success = proxy_core.server_controller.start_port(port)
                self.update_hub_list_item(port, success)
                if success:
                    self.sync_hub_proxy(port)

            # 確保 SpinBox 不會跟現有重複
            if saved_hubs:
                max_port = max([int(p) for p in saved_hubs.keys()])
                self.spin_hub_port.setValue(max_port + 1)

            # 更新下拉選單，以便還原 Rules 時能找到對應的 Proxy
            self.refresh_proxy_combobox()

            # 3. 還原 Rules
            saved_rules = data.get("rules", [])
            for r in saved_rules:
                # 動作轉換
                action_key = r.get('action_key')
                if action_key is None:
                    action_key = 0
                    if "DIRECT" in r.get('action', ''): action_key = 1
                    elif "BLOCK" in r.get('action', ''): action_key = 2

                # [Fixed] 正規化設定檔中可能存在的全形星號 (U+FF0A)
                target = rule_utils.normalize_rule_target(r['target'])
                hosts = rule_utils.normalize_rule_pattern(r.get('hosts'))
                ports = rule_utils.normalize_rule_pattern(r.get('ports'))

                # 停用中的規則只還原到清單，不進 DLL (勾選啟用時才注入)
                enabled = bool(r.get('enabled', True))

                # 代理解析:優先穩定識別 proxy_name,回退舊版 proxy_text 顯示字串
                pending = {'proxy_name': r.get('proxy_name', ''), 'proxy': r.get('proxy_text', '')}
                proxy_id, proxy_text = self._resolve_proxy(pending)

                # 呼叫 DLL (統一入口:處理 PID/名稱、協議轉換、能力 fallback)
                rid = 0
                if enabled:
                    rid = self.bridge.add_rule_ex(
                        r.get('type', 'Name'), target, hosts, ports,
                        r.get('proto', 'BOTH'), action_key, int(proxy_id))

                if rid > 0 or not enabled:
                    # [Fixed] 全部用 .get() 帶預設: 手工編輯的 config 缺鍵時,
                    # 單條壞規則只會被跳過/降級, 不會中斷其後所有規則的還原
                    self.rules.append({
                        'id': int(rid),
                        'enabled': enabled,
                        'type': r.get('type', 'Name'),
                        'target': target,
                        'hosts': hosts,
                        'ports': ports,
                        'proto': r.get('proto', 'BOTH'),
                        'action': r.get('action', ''),
                        'action_key': action_key,
                        'proxy': proxy_text,   # 顯示文字 (可能隨語系變動)
                        'proxy_name': pending['proxy_name'],  # 穩定識別 (持久化用)
                        'proxy_id': int(proxy_id),   # [Fixed] 最後已知 ID (刪代理重刷用)
                        'auto': bool(r.get('auto', False)),  # [控制 API] 自動加入標記
                    })

            self.refresh_rules_table()
            self.append_log(f"設定還原完成: 代理 {len(self.custom_proxies)} 個, 路由 {len(self.port_config)} 個, 規則 {len(self.rules)} 條")
            self.retranslate_ui()

        except Exception as e:
            self.append_log(f"還原設定失敗: {e}")
            import traceback
            traceback.print_exc()

    # [開機自動啟動] 依偏好套用 (工作存於工作排程器，設定檔只記偏好)
    def _apply_autostart(self, enabled):
        """套用「開機時自動啟動」偏好：需要時才建立/移除工作，並同步勾選框。"""
        if startup.is_supported():
            if enabled:
                # is_enabled() 會確認工作指向的執行檔仍存在；換版本後路徑
                # 失效時會回報未啟用，這裡順便重寫修正。
                if not startup.is_enabled() and not startup.enable():
                    self.append_log(self.t("無法設定開機自動啟動，請稍後再試。"))
            elif startup.is_enabled():
                startup.disable()
        if hasattr(self, 'chk_autostart'):
            actual = startup.is_enabled()
            self.chk_autostart.blockSignals(True)
            self.chk_autostart.setChecked(actual)
            self.chk_autostart.blockSignals(False)

    def on_autostart_changed(self, checked):
        """勾選/取消開機自動啟動 (登錄 Windows 工作排程器)。"""
        if checked:
            if not startup.enable():
                QMessageBox.warning(
                    self, self.t("錯誤"),
                    self.t("無法設定開機自動啟動，請稍後再試。"))
                self.chk_autostart.blockSignals(True)
                self.chk_autostart.setChecked(False)
                self.chk_autostart.blockSignals(False)
            else:
                self.append_log(self.t("已設定開機自動啟動"))
        else:
            startup.disable()
            self.append_log(self.t("已取消開機自動啟動"))
        self.save_config()

    # --------------------------------------------------------- 介面計量校正
    def on_manage_metric_changed(self, checked):
        """勾選後立即校正一次介面計量 (取消勾選則不還原既有設定)。"""
        if checked:
            self._sync_interface_metrics(force=True)
        self._request_save()

    def _sync_interface_metrics(self, force=False):
        """依設定在背景校正介面計量 (SoftEther 虛擬網卡 vs 實體網卡)。

        計量校正需要執行 PowerShell，會阻塞約 1 秒；放背景執行緒避免卡住
        UI，完成後以 metric_sync_done 訊號回到 UI 執行緒寫日誌。
        """
        if not force:
            chk = getattr(self, 'chk_manage_metric', None)
            if chk is not None and not chk.isChecked():
                return

        def work():
            try:
                result = interface_metrics.ensure_metrics()
            except Exception as e:  # noqa: BLE001 — 校正失敗不應影響主流程
                result = {"ok": False, "error": str(e)}
            self.metric_sync_done.emit(result)

        threading.Thread(target=work, daemon=True).start()

    def _on_metric_sync_done(self, result):
        result = result or {}
        if not result.get("ok"):
            if result.get("error"):
                self.append_log(f"介面計量校正失敗: {result['error']}")
            return
        if result.get("no_vpn"):
            self.append_log("介面計量校正: 尚未建立 SoftEther 虛擬網卡，略過")
            return
        parts = []
        if result.get("vpn"):
            parts.append(
                "虛擬網卡 {} 計量={}".format(
                    ", ".join(result["vpn"]), result.get("vpn_metric")))
        if result.get("physical"):
            parts.append(
                "實體網卡 {} 計量={}".format(
                    result["physical"], result.get("physical_metric")))
        if parts:
            self.append_log("介面計量校正: " + "；".join(parts))

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(14, 12, 14, 14)
        main_layout.setSpacing(12)

        # 提前建立日誌控制項：VPN Gate 分頁初始化時 (setup_vpngate_tab) 會
        # 在載入既有節點池後呼叫 vpn_apply_filters → append_log；若等到下方
        # log_group 才建立 txt_log，會在啟動時就先存取不存在的屬性而崩潰。
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setObjectName("LogView")

        # 頂部儀表列：第一列放服務總開關與全域狀態徽章，第二列放次要設定。
        # 全部擠在同一列時最小寬度達 1600px 以上，遠超過預設的 1024 視窗，
        # 會強制把視窗撐寬，在較小的螢幕上被裁掉。
        top_frame = QFrame()
        top_frame.setObjectName("TopBar")
        top_outer = QVBoxLayout(top_frame)
        top_outer.setContentsMargins(12, 8, 12, 8)
        top_outer.setSpacing(8)

        top_bar = QHBoxLayout()
        top_bar.setSpacing(10)
        self.btn_master_switch = QPushButton("")
        self.btn_master_switch.setCheckable(True)
        self.btn_master_switch.setMinimumHeight(34)
        self.btn_master_switch.setMinimumWidth(120)
        self.btn_master_switch.clicked.connect(self.toggle_redirector_service)
        top_bar.addWidget(self.btn_master_switch)
        
        self.lbl_status = QLabel("")
        top_bar.addWidget(self.lbl_status)

        # 全域狀態徽章 (核心延遲 / 活動轉發)
        self.lbl_ping_badge = QLabel("")
        top_bar.addWidget(self.lbl_ping_badge)

        self.lbl_conns_badge = QLabel("")
        top_bar.addWidget(self.lbl_conns_badge)

        self.combo_lang = QComboBox()
        self.combo_lang.setFixedWidth(150)
        for code in SUPPORTED_LANGS:
            self.combo_lang.addItem(tr.lang_name(code), code)
        self.combo_lang.currentIndexChanged.connect(self.on_lang_changed)

        # 設定與說明收進右上角一顆「⚙」彈出選單，避免佔用獨立選單列
        self.btn_menu = QPushButton("⚙")
        self.btn_menu.setFixedWidth(38)
        self.btn_menu.clicked.connect(self._show_overflow_menu)
        self._reg("tooltip", self.btn_menu, "設定")

        # [新增] Ping 目標設定 (預設 8.8.8.8，可依地區改為其他目標)
        lbl_ping = QLabel("")
        self._reg("text", lbl_ping, "Ping 目標:")
        self.ent_ping_target = QLineEdit(self.ping_target)
        self.ent_ping_target.setFixedWidth(120)
        self._reg("tooltip", self.ent_ping_target,
                  "網路介面延遲偵測的 Ping 目標 (IP 或域名)")
        self.ent_ping_target.editingFinished.connect(self.on_ping_target_changed)

        self.chk_minimize_to_tray = QCheckBox("")
        self._reg("text", self.chk_minimize_to_tray, "關閉時縮到系統匣")
        self.chk_minimize_to_tray.setChecked(False)
        self._reg("tooltip", self.chk_minimize_to_tray,
                  "勾選後，按關閉會直接縮到系統匣，不詢問")
        self.chk_minimize_to_tray.toggled.connect(self.on_pref_toggled)

        self.chk_check_updates = QCheckBox("")
        self._reg("text", self.chk_check_updates, "啟動時自動檢查更新")
        self.chk_check_updates.setChecked(self.check_updates_on_start)
        self.chk_check_updates.toggled.connect(self.on_pref_toggled)

        # [新增] 開機自動啟動 (預設開啟)；實際狀態存於工作排程器，
        # 於 load_config → _apply_autostart 時同步為真實狀態
        self.chk_autostart = QCheckBox("")
        self._reg("text", self.chk_autostart, "開機時自動啟動")
        self.chk_autostart.setChecked(True)
        self.chk_autostart.setToolTip(self.t(
            "登入 Windows 後自動以最高權限啟動本程式（不需 UAC 提示）。僅影響目前使用者。"))
        self.chk_autostart.toggled.connect(self.on_autostart_changed)

        # [新增] 自動管理介面計量：SoftEther 虛擬網卡建立時 IPv4 計量為「自動」，
        # 可能與實體網卡搶預設路由；勾選後自動校正 (需管理員權限，本程式已具備)。
        self.chk_manage_metric = QCheckBox("")
        self._reg("text", self.chk_manage_metric, "自動管理介面計量")
        self.chk_manage_metric.setChecked(True)
        self._reg("tooltip", self.chk_manage_metric,
                  "勾選後自動將 SoftEther 虛擬網卡計量設高、實體網卡設低，避免 VPN 搶走預設路由。")
        self.chk_manage_metric.toggled.connect(self.on_manage_metric_changed)

        top_bar.addStretch()
        top_bar.addWidget(self.combo_lang)
        top_bar.addWidget(self.btn_menu)
        top_outer.addLayout(top_bar)

        # 設定項目改放進「⚙」彈出選單，不再佔用頂部一整列。
        # 沿用原本的 QLabel / QCheckBox widget，i18n 註冊與存檔邏輯不需更動。
        self.menu_overflow = QMenu(self)

        ping_row = QWidget()
        ping_row_layout = QHBoxLayout(ping_row)
        ping_row_layout.setContentsMargins(10, 4, 12, 4)
        ping_row_layout.addWidget(lbl_ping)
        ping_row_layout.addWidget(self.ent_ping_target)
        ping_row_layout.addStretch()
        ping_action = QWidgetAction(self.menu_overflow)
        ping_action.setDefaultWidget(ping_row)
        self.menu_overflow.addAction(ping_action)
        self.menu_overflow.addSeparator()

        for chk in (self.chk_minimize_to_tray, self.chk_check_updates, self.chk_autostart,
                    self.chk_manage_metric):
            # 包一層容器補上下內距。QMenu::item 的 padding 不作用於
            # QWidgetAction 的 widget，直接放 QCheckBox 會三個緊貼在一起。
            chk_row = QWidget()
            chk_row_layout = QHBoxLayout(chk_row)
            chk_row_layout.setContentsMargins(10, 6, 12, 6)
            chk_row_layout.addWidget(chk)
            chk_row_layout.addStretch()
            chk_action = QWidgetAction(self.menu_overflow)
            chk_action.setDefaultWidget(chk_row)
            self.menu_overflow.addAction(chk_action)

        main_layout.addWidget(top_frame)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_hub = QWidget()
        self.setup_hub_tab()
        self.tabs.addTab(self.tab_hub, "")
        self._reg("tab", self.tabs, 0, "1. 端口路由管理")

        self.tab_rules = QWidget()
        self.setup_rules_tab()
        self.tabs.addTab(self.tab_rules, "")
        self._reg("tab", self.tabs, 1, "2. 進程攔截規則")

        self.tab_proxies = QWidget()
        self.setup_custom_proxy_tab()
        self.tabs.addTab(self.tab_proxies, "")
        self._reg("tab", self.tabs, 2, "3. 自訂代理管理")

        self.tab_monitor = QWidget()
        self.setup_monitor_tab()
        self.tabs.addTab(self.tab_monitor, "")
        self._reg("tab", self.tabs, 3, "4. 流量監控")

        self.tab_vpngate = QWidget()
        self.setup_vpngate_tab()
        self.tabs.addTab(self.tab_vpngate, "")
        self._reg("tab", self.tabs, 4, "5. VPN Gate 節點派發")

        log_group = QGroupBox("")
        self._reg("title", log_group, "系統日誌")
        log_layout = QVBoxLayout()
        log_layout.addWidget(self.txt_log)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)
        
        main_layout.setStretch(1, 4) 
        main_layout.setStretch(2, 1)

        self.update_service_status()
        self.update_hub_status()

    # (以下為各 Tab 的 setup 函式，與原版相同)
    def on_network_update(self, interfaces):
        self.current_interfaces = interfaces
        proxy_core.route_manager.sync_interfaces(interfaces)
        self.update_dashboard_badges()
        if self.tabs.currentIndex() == 0:
            self.refresh_hub_table()
        if hasattr(self, 'table_vpn_nics'):
            self._vpn_update_live_status()

    def on_traffic_event(self, process, pid, ip, port, info):
        if pid == os.getpid():
            return  # 不顯示本程式自己產生的流量
        # 列插入 / 篩選 / 捲動 / 計數集中在 MonitorTabMixin (tabs_monitor.py)
        self.append_traffic_row(process, pid, ip, port, info)

    def on_dll_log(self, msg):
        self.append_log(f"[DLL] {msg}")

    def append_log(self, msg):
        self.txt_log.append(msg)
        c = self.txt_log.textCursor()
        c.movePosition(c.MoveOperation.End)
        self.txt_log.setTextCursor(c)

    # --------------------------------------------------------- 自動更新
    def _setup_overflow_menu(self):
        """把「自動直連偵測 / 檢查更新 / 關於」併入右上角「⚙」選單。"""
        # 自動直連偵測開關：關閉後不再自動加入；重新開啟會把預設清單的項目
        # 補回並立即掃描一次，作為使用者刪除自動規則後的復原入口。
        # 這裡用 QCheckBox 包 QWidgetAction，而不是可勾選的 QAction：QAction 的
        # 勾勾由 Qt 原生 QMenu::indicator 繪製，在深色主題下只會是一個沒有方框
        # 的白勾，跟上方設定列的 QCheckBox 指示器對不齊。沿用同一種列才一致。
        self.chk_auto_direct = QCheckBox("")
        self._reg("text", self.chk_auto_direct, "自動偵測並加入直連程式")
        self.chk_auto_direct.setChecked(
            bool(getattr(self, "auto_direct_enabled", True)))
        self.chk_auto_direct.toggled.connect(self.on_auto_direct_toggled)
        auto_row = QWidget()
        auto_row_layout = QHBoxLayout(auto_row)
        auto_row_layout.setContentsMargins(10, 6, 12, 6)
        auto_row_layout.addWidget(self.chk_auto_direct)
        auto_row_layout.addStretch()
        auto_action = QWidgetAction(self.menu_overflow)
        auto_action.setDefaultWidget(auto_row)
        self.menu_overflow.addAction(auto_action)

        self.menu_overflow.addSeparator()

        self.act_check_update = self.menu_overflow.addAction(self.t("檢查更新"))
        self.act_check_update.triggered.connect(lambda: self.check_for_updates(silent=False))

        self.act_about = self.menu_overflow.addAction(self.t("關於"))
        self.act_about.triggered.connect(self._show_about)

        # 註冊 i18n (切換語言時重譯選單文字)
        self._reg("text", self.act_check_update, "檢查更新")
        self._reg("text", self.act_about, "關於")

    def _show_overflow_menu(self):
        """在「⚙」按鈕正下方彈出設定/說明選單。"""
        self.menu_overflow.exec(
            self.btn_menu.mapToGlobal(QPoint(0, self.btn_menu.height())))

    def _show_about(self):
        QMessageBox.about(
            self,
            self.t("關於 NetRedirector"),
            f"{self.t('NetRedirector x GameProxyHub 整合專業版')}\n\n"
            f"{self.t('版本:')} {APP_VERSION}"
        )

    def _on_startup_update_check(self):
        """啟動時若「自動檢查更新」已勾選，且本次尚未檢查過，則背景查一次。"""
        if self.check_updates_on_start and not self._update_checked:
            self._update_checked = True
            self.check_for_updates(silent=True)

    def check_for_updates(self, silent=False):
        if self.update_worker is not None and self.update_worker.isRunning():
            return
        if not silent:
            self.append_log(self.t("正在檢查更新..."))
        self.update_worker = UpdateWorker(APP_VERSION)
        self.update_worker.result.connect(
            lambda r: self._on_update_check_result(r, silent))
        self.update_worker.start()

    def _on_update_check_result(self, result, silent):
        if isinstance(result, Exception):
            msg = f"{self.t('檢查更新失敗:')} {result}"
            self.append_log(msg)
            if not silent:
                QMessageBox.warning(self, self.t("檢查更新"), msg)
            return
        if result is None:
            if not silent:
                QMessageBox.information(self, self.t("檢查更新"), self.t("已是最新版本。"))
            return
        # 有新版本 → 詢問是否下載安裝
        text = self.t("發現新版本 {v}，是否下載並安裝？").format(v=result["version"])
        reply = QMessageBox.question(self, self.t("檢查更新"), text)
        if reply == QMessageBox.StandardButton.Yes:
            self._start_stage(result)

    def _start_stage(self, info):
        if self.stage_worker is not None and self.stage_worker.isRunning():
            return
        self.act_check_update.setEnabled(False)
        self.append_log(self.t("正在下載更新..."))
        # 多線程下載可能仍要數分鐘，顯示進度與取消鈕讓使用者知道不是卡住
        self._update_dialog = QProgressDialog(
            self.t("正在下載更新..."), self.t("取消"), 0, 100, self)
        self._update_dialog.setWindowTitle(self.t("檢查更新"))
        self._update_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._update_dialog.setMinimumDuration(0)
        self._update_dialog.setAutoClose(False)
        self._update_dialog.setAutoReset(False)
        self._update_dialog.setValue(0)
        self._update_dialog.canceled.connect(self._cancel_stage)
        self._update_dialog.show()
        self.stage_worker = StageWorker(info)
        self.stage_worker.progress.connect(self._on_stage_progress)
        self.stage_worker.log.connect(self.append_log)
        self.stage_worker.result.connect(self._on_stage_result)
        self.stage_worker.start()

    def _on_stage_progress(self, info):
        dlg = getattr(self, "_update_dialog", None)
        if dlg is None or not info:
            return
        total = int(info.get("total") or 0)
        done = int(info.get("downloaded") or 0)
        pct = int(done * 100 / total) if total > 0 else 0
        dlg.setValue(min(100, pct))
        dlg.setLabelText(self.t(
            "已下載 {done} / {total}（{pct}%）　速度 {speed}/s　連線 {threads}").format(
                done=_fmt_bytes(done), total=_fmt_bytes(total), pct=pct,
                speed=_fmt_bytes(int(info.get("speed") or 0)),
                threads=int(info.get("threads") or 1)))

    def _cancel_stage(self):
        if self.stage_worker is not None and self.stage_worker.isRunning():
            self.stage_worker.cancel()

    def _on_stage_result(self, result):
        dlg = getattr(self, "_update_dialog", None)
        if dlg is not None:
            dlg.close()
            self._update_dialog = None
        self.act_check_update.setEnabled(True)
        if isinstance(result, updater.UpdateCancelled):
            self.append_log(self.t("已取消更新下載。"))
            return
        if isinstance(result, Exception):
            msg = f"{self.t('檢查更新失敗:')} {result}"
            self.append_log(msg)
            QMessageBox.warning(self, self.t("檢查更新"), msg)
            return
        text = self.t("更新下載完成，重新啟動後生效。是否立即重新啟動？")
        reply = QMessageBox.question(self, self.t("檢查更新"), text)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                updater.apply_and_restart()
            except Exception as e:
                QMessageBox.warning(self, self.t("檢查更新"), str(e))
                return
            self._really_quit = True
            self._perform_shutdown()
            QApplication.instance().quit()

    # --------------------------------------------------------- 系統匣
    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray_icon = None
            return
        self._tray_icon = QSystemTrayIcon(self._app_icon, self)
        self._tray_icon.setToolTip(self.t("NetRedirector x GameProxyHub 整合專業版"))

        self.menu_tray = QMenu()
        self.act_tray_show = self.menu_tray.addAction(self.t("顯示主視窗"))
        self.act_tray_show.triggered.connect(self._restore_from_tray)
        self.act_tray_quit = self.menu_tray.addAction(self.t("完全關閉程式"))
        self.act_tray_quit.triggered.connect(self._quit_from_tray)
        # 註冊 i18n，切換語言時系統匣選單才會跟著重譯
        self._reg("text", self.act_tray_show, "顯示主視窗")
        self._reg("text", self.act_tray_quit, "完全關閉程式")
        self._tray_icon.setContextMenu(self.menu_tray)

        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.show()

    def _on_tray_activated(self, reason):
        # 單擊/雙擊 tray 圖示都還原視窗
        if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                      QSystemTrayIcon.ActivationReason.DoubleClick):
            self._restore_from_tray()

    def _restore_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # 最小化時也縮到系統匣 (迅雷式行為)
    def changeEvent(self, event):
        super().changeEvent(event)
        if (event.type() == QEvent.Type.WindowStateChange
                and self.isMinimized()
                and self._tray_icon is not None):
            # 延後執行，避免在視窗狀態事件內直接 hide 造成閃爍/狀態錯亂
            QTimer.singleShot(0, self._hide_to_tray)

    def _hide_to_tray(self):
        self.hide()
        if self._tray_icon and not self._tray_notified:
            self._tray_icon.showMessage(
                self.t("NetRedirector"),
                self.t("程式已縮到系統匣繼續運作，點擊圖示可重新開啟。"),
                QSystemTrayIcon.MessageIcon.Information, 3000,
            )
            self._tray_notified = True

    def _quit_from_tray(self):
        self._really_quit = True
        try:
            self._perform_shutdown()
        finally:
            # 直接退出事件迴圈，避免視窗已隱藏(縮到匣)時 close() 未觸發 closeEvent 而卡住
            QApplication.instance().quit()

    def _perform_shutdown(self):
        if getattr(self, '_shutdown_done', False):
            return
        self._shutdown_done = True

        # 先關本機控制 API：關閉流程中不該再接受外部請求進來改規則
        if getattr(self, 'control_api', None) is not None:
            self.control_api.stop()

        # [診斷] 逐段計時寫入 shutdown_timing.log，定位關閉慢的步驟
        marks = []
        t0 = time.perf_counter()

        # 已有待寫變更時不需再等自動存檔計時器，由這次的 save_config 落地
        if self._save_scheduler is not None:
            self._save_scheduler.cancel()
        self.save_config()
        marks.append(("save_config", time.perf_counter() - t0))

        t1 = time.perf_counter()
        self.monitor_thread.stop()
        marks.append(("monitor_thread.stop", time.perf_counter() - t1))

        t2 = time.perf_counter()
        if self.is_redirector_running:
            self.bridge.stop()
        marks.append(("bridge.stop", time.perf_counter() - t2))

        t3 = time.perf_counter()
        proxy_core.server_controller.stop_all()
        marks.append(("server.stop_all", time.perf_counter() - t3))

        if self._tray_icon:
            self._tray_icon.hide()

        try:
            with open("shutdown_timing.log", "w", encoding="utf-8") as f:
                for name, dt in marks:
                    f.write(f"{name}: {dt*1000:.0f} ms\n")
        except OSError:
            pass

    # [新增] 關閉視窗：視「縮到系統匣」設定決定直接離開、直接縮匣或詢問
    def closeEvent(self, event):
        if self._really_quit:
            self._perform_shutdown()
            event.accept()
            return

        # 系統匣不可用時，直接正常關閉
        if self._tray_icon is None:
            self._perform_shutdown()
            event.accept()
            return

        if self.chk_minimize_to_tray.isChecked():
            self._hide_to_tray()
            event.ignore()
            return

        # 詢問：完全關閉 or 縮到系統匣 (二選一，無取消/記住選項)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(self.t("關閉 NetRedirector"))
        box.setText(self.t("要完全關閉程式，還是縮到系統匣？"))
        btn_quit = box.addButton(self.t("完全關閉"), QMessageBox.ButtonRole.DestructiveRole)
        btn_tray = box.addButton(self.t("縮到系統匣"), QMessageBox.ButtonRole.AcceptRole)
        box.setDefaultButton(btn_tray)
        box.exec()

        clicked = box.clickedButton()
        if clicked is btn_quit:
            self._perform_shutdown()
            event.accept()
            return
        if clicked is btn_tray:
            # 連動介面上的設定：下次按關閉會直接縮匣，除非手動改設定
            self.chk_minimize_to_tray.setChecked(True)
            self.save_config()
            self._hide_to_tray()
            event.ignore()
            return
        # 對話框被 Esc / 右上角 X 關掉時，維持程式開啟
        event.ignore()

if __name__ == '__main__':
    # 由工作排程器啟動時工作目錄是 System32，先切到程式所在資料夾，
    # 否則 NetRedirector.dll / config.json / locale 等相對路徑會找不到。
    startup.ensure_working_directory()

    try: is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception: is_admin = False

    # 單一實例：已有程式在跑就帶到前景後結束，不開第二個
    mutex_handle, already_running = single_instance.acquire_mutex()
    if already_running:
        single_instance.bring_existing_to_front()
        sys.exit(0)

    app = QApplication(sys.argv)

    # [現代化 UI] 全域深色主題。QSS 與 QPalette 必須一起套用：表格左上角、
    # 捲軸交會角、核取方塊指示器、彈出選單等原生繪製的部分不吃 QSS。
    ui_theme.apply_dark_palette(app)
    app.setStyleSheet(ui_theme.build_stylesheet())

    # 全域預設圖示 (工作列/Alt-Tab 切換時顯示)
    app.setWindowIcon(get_app_icon())

    # Windows 工作列圖示分組：讓工作列顯示自訂 icon 而非 python 圖示
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "NetRedirector.GameProxyHub")
    except Exception:
        pass

    if not is_admin:
        QMessageBox.warning(None, tr.t("權限不足"), tr.t("請以管理員身分執行！"))
        single_instance.release_mutex(mutex_handle)
        sys.exit(1)

    window = MainWindow()
    window.show()
    exit_code = app.exec()
    single_instance.release_mutex(mutex_handle)
    sys.exit(exit_code)