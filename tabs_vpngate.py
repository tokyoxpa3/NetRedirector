# -*- coding: utf-8 -*-
"""VPN Gate 節點派發分頁 mixin (自 vpngate-auto-assign 融入)

左側: SoftEther 虛擬網卡清單 (狀態/伺服器) + 選取後一鍵上線。
右側: VPN Gate 節點清單 + 篩選 (排除 public-*、port 443、最低速度、國家)。

跨次啟動累積節點池 (vpn_history): 以 ip 去重、依長期連線經驗計算穩定度，
派發排序以穩定度為準。會話監視器偵測離線與「假連線」(SoftEther 顯示連線
但 tunnel 實際已死)，非預期中斷後自動換到下一台最穩定的節點。

所有慢速操作 (vpncmd、抓節點、連線) 都在背景執行緒執行，結果透過
queue 送回 UI 執行緒 (QTimer 輪詢)，避免凍結主執行緒。
"""

import concurrent.futures
import ipaddress
import queue
import socket
import subprocess
import threading
import time

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget,
                               QTableWidgetItem, QPushButton, QLabel, QGroupBox,
                               QCheckBox, QSpinBox, QListWidget, QHeaderView,
                               QMessageBox, QSplitter)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor, QBrush

from i18n import i18n as tr
import vpngate_config as config
import vpngate
import vpn_history
import softether


_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _ps_ipv4_map():
    """單一 PowerShell 查詢所有介面的 IPv4，回傳 {InterfaceAlias: IPv4}。

    取代每張網卡各開一次 PowerShell；介面別名常是「VPN2 - VPN Client」，
    由 _lookup_nic_ip 做寬鬆前綴比對 (避免 VPN2 誤配 VPN20)。
    """
    try:
        out = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue "
                "| ForEach-Object { $_.InterfaceAlias + '|' + $_.IPAddress }",
            ],
            capture_output=True,
            timeout=30,
            creationflags=_CREATE_NO_WINDOW,
        )
        text = out.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        return {}
    mapping = {}
    for line in text.splitlines():
        if "|" not in line:
            continue
        alias, _, ip = line.partition("|")
        alias = alias.strip()
        ip = ip.strip()
        if alias and alias not in mapping:
            try:
                ipaddress.IPv4Address(ip)
            except ValueError:
                continue
            mapping[alias] = ip
    return mapping


def _lookup_nic_ip(ip_map, nic):
    """依 NIC 名稱從介面對照表取 IPv4，找不到回傳 None。"""
    for alias, ip in ip_map.items():
        if alias == nic or alias.startswith(f"{nic} ") or alias.startswith(f"{nic} -"):
            return ip
    return None


def _ps_ipv4(nic):
    """回傳 nic 的 IPv4 (寬鬆比對)，找不到回傳 None。"""
    return _lookup_nic_ip(_ps_ipv4_map(), nic)


def _tunnel_reachable(source_ip, target="1.1.1.1", port=443, timeout=8):
    """綁定 source_ip 連 1.1.1.1:443 驗證 tunnel 有實際轉發流量。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.bind((source_ip, 0))
        sock.connect((target, port))
        sock.close()
        return True
    except Exception:
        return False


def _fmt_duration(sec):
    """把秒數轉成易讀字串 (12s / 45m / 2.5h)。"""
    sec = int(sec)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m"
    return f"{sec / 3600:.1f}h"


def _wait_connected(se, nic, timeout=None):
    if timeout is None:
        timeout = config.CONNECT_TIMEOUT
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if se.is_connected(nic):
            return True
        time.sleep(config.STATUS_POLL_INTERVAL)
    return False


class VpnGateTabMixin:
    def setup_vpngate_tab(self):
        layout = QHBoxLayout(self.tab_vpngate)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ---------- 左: NIC 清單 ----------
        left_panel = QGroupBox("")
        self._reg("title", left_panel, "SoftEther 虛擬網卡")
        left_layout = QVBoxLayout()

        self.table_vpn_nics = QTableWidget()
        self.table_vpn_nics.setColumnCount(3)
        self._reg("headers", self.table_vpn_nics,
                  ["網卡名", "狀態", "伺服器"])
        # 固定欄位依內容自動收合 (i18n 安全)，伺服器(IP:port)變動欄位才伸展
        self.table_vpn_nics.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nics.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nics.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_vpn_nics.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_vpn_nics.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        left_layout.addWidget(self.table_vpn_nics)

        nic_btns = QHBoxLayout()
        btn_refresh = QPushButton("")
        self._reg("text", btn_refresh, "重新整理網卡")
        btn_refresh.clicked.connect(self.vpn_refresh_nics)
        btn_connect = QPushButton("")
        self._reg("text", btn_connect, "一鍵上線")
        btn_connect.setStyleSheet("background-color: #4CAF50; color: white;")
        btn_connect.clicked.connect(self.vpn_connect_all)
        btn_connect_selected = QPushButton("")
        self._reg("text", btn_connect_selected, "連線選取節點")
        btn_connect_selected.clicked.connect(self.vpn_connect_selected)
        nic_btns.addWidget(btn_refresh)
        nic_btns.addWidget(btn_connect)
        nic_btns.addWidget(btn_connect_selected)
        left_layout.addLayout(nic_btns)

        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)

        # ---------- 右: 節點清單 + 篩選 ----------
        right_panel = QGroupBox("")
        self._reg("title", right_panel, "VPN Gate 節點列表")
        right_layout = QVBoxLayout()

        filter_group = QGroupBox("")
        self._reg("title", filter_group, "篩選條件")
        filter_layout = QHBoxLayout()
        self.chk_vpn_excl_public = QCheckBox("")
        self._reg("text", self.chk_vpn_excl_public, "排除 public-* 節點")
        self.chk_vpn_excl_public.setChecked(True)
        self.chk_vpn_excl_443 = QCheckBox("")
        self._reg("text", self.chk_vpn_excl_443, "排除 port 443")
        self.chk_vpn_excl_443.setChecked(True)
        lbl_min_speed = QLabel("")
        self._reg("text", lbl_min_speed, "最低速度(Mbps):")
        self.spin_vpn_min_speed = QSpinBox()
        self.spin_vpn_min_speed.setRange(1, 1000)
        self.spin_vpn_min_speed.setValue(config.MIN_SPEED_BPS // 1_000_000)
        self.spin_vpn_min_speed.setFixedWidth(70)
        filter_layout.addWidget(self.chk_vpn_excl_public)
        filter_layout.addWidget(self.chk_vpn_excl_443)
        filter_layout.addWidget(lbl_min_speed)
        filter_layout.addWidget(self.spin_vpn_min_speed)
        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        right_layout.addWidget(filter_group)

        country_layout = QHBoxLayout()
        lbl_country = QLabel("")
        self._reg("text", lbl_country, "所在地(多選，空=全部):")
        self.list_vpn_countries = QListWidget()
        self.list_vpn_countries.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.list_vpn_countries.setFixedHeight(90)
        country_layout.addWidget(lbl_country)
        country_layout.addWidget(self.list_vpn_countries, 1)
        right_layout.addLayout(country_layout)

        node_btns = QHBoxLayout()
        btn_fetch = QPushButton("")
        self._reg("text", btn_fetch, "抓取節點")
        btn_fetch.clicked.connect(self.vpn_fetch_nodes)
        btn_apply = QPushButton("")
        self._reg("text", btn_apply, "套用篩選")
        btn_apply.clicked.connect(self.vpn_apply_filters)
        node_btns.addWidget(btn_fetch)
        node_btns.addWidget(btn_apply)
        node_btns.addStretch()
        right_layout.addLayout(node_btns)

        self.table_vpn_nodes = QTableWidget()
        self.table_vpn_nodes.setColumnCount(13)
        self._reg("headers", self.table_vpn_nodes,
                  ["主機名", "IP", "Port", "穩定度", "成功率", "平均時長",
                   "被踢", "Score", "Ping", "速度", "國家", "失敗", "上次見"])
        # 短數值欄位依內容自動收合；主機名、國家等長文字才伸展
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(9, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(11, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(12, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_vpn_nodes.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_vpn_nodes.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        right_layout.addWidget(self.table_vpn_nodes, 1)

        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

        # ---------- 背景執行緒 → UI 佇列 ----------
        self.vpn_queue = queue.Queue()
        self.vpn_se = softether.SoftEtherClient()
        self.vpn_history = vpn_history.load_history()  # 跨次啟動的節點池
        self.vpn_all_nodes = []
        self.vpn_candidates = []
        self.vpn_fail_count = {}      # ip -> 本次執行中的連續失敗次數 (排序用)
        self.vpn_session_state = {}   # nic -> {node_ip, ip, started_at, unhealthy_streak}
        self.vpn_assigning = False    # 指派進行中旗標 (避免重疊指派)
        self.vpn_timer = QTimer()
        self.vpn_timer.timeout.connect(self._vpn_poll_queue)
        self.vpn_timer.start(100)
        self.vpn_monitor_timer = QTimer()
        self.vpn_monitor_timer.timeout.connect(self._vpn_monitor_tick)
        self.vpn_monitor_timer.start(config.SESSION_POLL_INTERVAL * 1000)

        # 啟動即載入池子，讓使用者未抓取也能瀏覽累積節點
        self._vpn_rebuild_all_nodes()
        self._vpn_fill_countries()
        if self.vpn_all_nodes:
            self.vpn_apply_filters()

    # --------------------------------------------------------- 佇列 / 執行緒
    def _vpn_post(self, fn, *args):
        self.vpn_queue.put((fn, args))

    def _vpn_poll_queue(self):
        try:
            while True:
                fn, args = self.vpn_queue.get_nowait()
                fn(*args)
        except queue.Empty:
            pass

    def _vpn_run_bg(self, fn, done=None):
        def worker():
            try:
                result = fn()
            except Exception as e:
                self._vpn_post(self._vpn_log_error, str(e))
                result = None
            if done:
                self._vpn_post(done, result)
        threading.Thread(target=worker, daemon=True).start()

    def _vpn_log(self, msg):
        self.append_log(f"[VPN Gate] {msg}")

    def _vpn_log_error(self, msg):
        self.append_log(f"[VPN Gate] 錯誤: {msg}")

    def _vpn_rec(self, node):
        """取得節點在池子裡的記錄 (無則回空 dict)。"""
        return self.vpn_history.get("nodes", {}).get(node.ip, {})

    def _vpn_stability(self, node):
        return vpn_history.stability(self._vpn_rec(node))

    # --------------------------------------------------------- NIC 面板
    def vpn_refresh_nics(self):
        self._vpn_log("重新整理網卡狀態…")

        def work():
            nics = self.vpn_se.nic_list()
            servers = self.vpn_se.account_servers()
            rows = []
            for nic in nics:
                srv = servers.get(nic)
                server_s = f"{srv[0]}:{srv[1]}" if srv else ""
                rows.append((nic, server_s))
            return rows

        self._vpn_run_bg(work, done=self._vpn_render_nics)

    def _vpn_nic_online(self, nic, interfaces):
        for name, data in interfaces.items():
            if name == nic or name.startswith(f"{nic} ") or name.startswith(f"{nic} -"):
                return bool(data.get('ipv4'))
        return False

    def _vpn_update_live_status(self):
        table = getattr(self, 'table_vpn_nics', None)
        if table is None:
            return
        interfaces = getattr(self, 'current_interfaces', {})
        for row in range(table.rowCount()):
            nic_item = table.item(row, 0)
            if not nic_item:
                continue
            online = self._vpn_nic_online(nic_item.text(), interfaces)
            status_item = table.item(row, 1)
            if status_item is None:
                status_item = QTableWidgetItem()
                table.setItem(row, 1, status_item)
            status_item.setText(self.t("上線") if online else self.t("離線"))
            status_item.setForeground(QBrush(QColor("#4CAF50") if online else QColor("#F44336")))

    def _vpn_render_nics(self, rows):
        self.vpn_nic_names = [r[0] for r in rows]
        self.table_vpn_nics.setRowCount(0)
        for nic, server in rows:
            row = self.table_vpn_nics.rowCount()
            self.table_vpn_nics.insertRow(row)
            self.table_vpn_nics.setItem(row, 0, QTableWidgetItem(nic))
            self.table_vpn_nics.setItem(row, 1, QTableWidgetItem(""))
            self.table_vpn_nics.setItem(row, 2, QTableWidgetItem(server))
        self._vpn_update_live_status()
        self._vpn_log(f"網卡狀態更新完成（{len(rows)} 個）")

    def _vpn_used_server_ips(self, exclude=None):
        exclude = exclude or set()
        ips = set()
        for nic in self.vpn_se.account_list():
            if nic in exclude:
                continue
            server = self.vpn_se.account_server(nic)
            if server and server[0]:
                ips.add(server[0])
        return ips

    def vpn_connect_all(self):
        if self.vpn_assigning:
            self._vpn_log("已有指派進行中，略過本次")
            return
        nics = list(getattr(self, 'vpn_nic_names', []) or [])
        if not nics:
            QMessageBox.information(self, self.t("提示"), self.t("尚無虛擬網卡，請先重新整理網卡"))
            return
        interfaces = getattr(self, 'current_interfaces', {})
        offline = [n for n in nics if not self._vpn_nic_online(n, interfaces)]
        if not offline:
            self._vpn_log("所有網卡皆已在線，無需處理")
            return
        if not self.vpn_candidates:
            self._vpn_log("尚未抓取節點或篩選後無節點，請先抓取/套用篩選")
            return
        self.vpn_assigning = True
        self._vpn_run_bg(lambda: self._vpn_assign_nics(offline), done=self._vpn_after_assign)

    def vpn_connect_selected(self):
        """手動指定單一網卡連多個選取節點，依序嘗試直到 tunnel 可通。"""
        if self.vpn_assigning:
            self._vpn_log("已有指派進行中，略過本次")
            return
        selected_nics = self.table_vpn_nics.selectionModel().selectedRows()
        if not selected_nics:
            QMessageBox.information(
                self, self.t("提示"), self.t("請先在左側選取一張網卡"),
            )
            return
        nic = self.table_vpn_nics.item(selected_nics[0].row(), 0).text()
        rows = sorted(
            idx.row() for idx in self.table_vpn_nodes.selectionModel().selectedRows()
        )
        nodes = [n for n in (self._vpn_row_node(r) for r in rows) if n is not None]
        if not nodes:
            QMessageBox.information(
                self, self.t("提示"), self.t("請先在右側選取至少一個節點"),
            )
            return
        self.vpn_assigning = True
        self._vpn_run_bg(
            lambda: self._vpn_assign_fallback(nic, nodes), done=self._vpn_after_assign,
        )

    def _vpn_row_node(self, row):
        """依表格列索引取回渲染當下的節點 (無則回 None)。"""
        nodes = getattr(self, "vpn_row_nodes", [])
        if 0 <= row < len(nodes):
            return nodes[row]
        return None

    def _vpn_assign_fallback(self, nic, nodes):
        """對單一網卡依序嘗試 nodes，第一個 tunnel 可通者勝出。

        失敗定義沿用 _vpn_assign_one：只要 tunnel_ok 不是 True 就換下一個。
        回傳結構與 _vpn_assign_nics 一致，可直接交給 _vpn_after_assign。
        """
        results = {}
        outcomes = []
        self._vpn_post(
            self._vpn_log, f"[{nic}] 手動指派（{len(nodes)} 個節點，依序嘗試）…",
        )
        for i, node in enumerate(nodes, 1):
            self._vpn_post(
                self._vpn_log,
                f"  -> 嘗試 {i}/{len(nodes)} {node.hostname} {node.ip}:{node.port} "
                f"({node.country_long})",
            )
            ok, tunnel_ok, ip = self._vpn_assign_one(nic, node)
            outcomes.append((node.ip, ok, tunnel_ok))
            if tunnel_ok is True:
                results[nic] = {"node": node, "ip": ip}
                break
        if not results:
            self._vpn_post(self._vpn_log, f"  X {nic} 所有選取節點皆連線失敗")
        return {"results": results, "outcomes": outcomes}

    def _vpn_assign_nics(self, nics, exclude_ips=None):
        exclude_ips = set(exclude_ips or [])
        failed = self.vpn_fail_count
        used_ips = self._vpn_used_server_ips(exclude=set(nics))
        # 本次失敗次數高的排後；穩定度高的優先 (取代官方 Score)
        candidates = sorted(
            self.vpn_candidates,
            key=lambda n: (failed.get(n.ip, 0), -self._vpn_stability(n)),
        )

        # 節點分配器: lock 保護 cursor / used，多張卡平行連線時不會搶到同一
        # 個節點；每個候選節點最多只被嘗試一次 (沿用原循序版的語意)。
        lock = threading.Lock()
        outcomes = []
        state = {"cursor": 0, "used": set(used_ips)}
        max_attempts = 10

        def alloc_node():
            with lock:
                while state["cursor"] < len(candidates):
                    node = candidates[state["cursor"]]
                    state["cursor"] += 1
                    if node.ip in state["used"] or node.ip in exclude_ips:
                        continue
                    state["used"].add(node.ip)
                    return node
                return None

        attempts = {nic: 0 for nic in nics}
        results = {}
        workers = min(config.PARALLEL_ASSIGN_WORKERS, max(1, len(nics)))

        for nic in nics:
            self._vpn_post(self._vpn_log, f"[{nic}] 開始指派…")

        def connect_one(nic):
            """取一個節點並嘗試建立 session；成功回傳 (nic, node)，失敗回 (nic, None)。"""
            node = alloc_node()
            if node is None:
                return nic, None
            attempts[nic] += 1
            self._vpn_post(
                self._vpn_log,
                f"  -> 嘗試 {node.hostname} {node.ip}:{node.port} "
                f"({node.country_long}, score={node.score})",
            )
            if self._vpn_connect_only(nic, node):
                return nic, node
            with lock:
                outcomes.append((node.ip, False, None))
                failed[node.ip] = failed.get(node.ip, 0) + 1
            return nic, None

        # 兩階段 (並行連線 → 批次查 IP → 並行驗證) 外包一層重試：session 建立
        # 失敗或驗證失敗的卡，下一輪回到分配器換新節點，而非只試單一節點就放棄。
        while True:
            # 每輪反推尚未成功指派的卡，避免漏掉「session 失敗」的網卡。
            pending = [n for n in nics if n not in results]
            round_nics = [n for n in pending if attempts[n] < max_attempts]
            if not round_nics:
                break
            with lock:
                nodes_exhausted = state["cursor"] >= len(candidates)
            if nodes_exhausted:
                break

            # 連線回合：並行嘗試建立 session（session 不通者下回合再換節點）
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                connected = [
                    r for r in ex.map(connect_one, round_nics) if r[1] is not None
                ]

            if not connected:
                continue  # 本回合全部 session 建立失敗，下一輪重試

            # 批次查一次所有網卡 IPv4；SoftEther 派發 IP 有短暫延遲，缺的就補輪詢。
            ip_map = _ps_ipv4_map()
            missing = [n for n, _ in connected if _lookup_nic_ip(ip_map, n) is None]
            if missing:
                deadline = time.time() + config.IP_WAIT_TIMEOUT
                while missing and time.time() < deadline:
                    time.sleep(config.IP_POLL_INTERVAL)
                    fresh = _ps_ipv4_map()
                    for alias, ip in fresh.items():
                        ip_map.setdefault(alias, ip)
                    missing = [
                        n for n in missing if _lookup_nic_ip(ip_map, n) is None
                    ]

            # 驗證 IP + tunnel（並行，避免循序掃描造成慢速）
            def verify_one(nic, node):
                ip = _lookup_nic_ip(ip_map, nic)
                if ip is None:
                    return nic, node, None, False
                self._vpn_post(self._vpn_log, f"     + 已連線，指派 IP {ip}")
                if self._vpn_tunnel_ok(ip):
                    self._vpn_post(self._vpn_log, f"     + tunnel 可通 ({ip})")
                    return nic, node, ip, True
                return nic, node, ip, False

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                verified = list(
                    ex.map(lambda e: verify_one(e[0], e[1]), connected)
                )

            for nic, node, ip, ok in verified:
                if ok:
                    results[nic] = {"node": node, "ip": ip}
                    with lock:
                        outcomes.append((node.ip, True, True))
                        failed.pop(node.ip, None)  # 連線成功，失敗計數歸零
                else:
                    if ip is None:
                        self._vpn_post(self._vpn_log, "     ! NIC 未取得 IP")
                    else:
                        self._vpn_post(self._vpn_log, "     ! tunnel 不通")
                    self.vpn_se.account_disconnect(nic)
                    with lock:
                        outcomes.append(
                            (node.ip, True, False if ip is not None else None)
                        )
                        failed[node.ip] = failed.get(node.ip, 0) + 1

        for nic in nics:
            if nic not in results:
                self._vpn_post(self._vpn_log, f"  X 無法為 {nic} 指派可用節點")

        return {"results": results, "outcomes": outcomes}

    def _vpn_connect_only(self, nic, node):
        """把 nic 連到 node 並等待 session 建立，不做 IP/tunnel 驗證。

        回傳 True 表示 session 已連線 (供平行指派與單卡 fallback 共用)。
        """
        self.vpn_se.account_disconnect(nic)
        self.vpn_se.account_set(nic, node.ip, node.port)
        self.vpn_se.account_set_anonymous(nic)
        self.vpn_se.account_connect(nic)
        if not _wait_connected(self.vpn_se, nic):
            self._vpn_post(self._vpn_log, "     ! session 未建立")
            return False
        return True

    def _vpn_tunnel_ok(self, ip):
        """短暫重試 tunnel 探測，避免 IP 剛出現時路由尚未收斂造成誤判。"""
        for attempt in range(config.TUNNEL_CHECK_ATTEMPTS):
            if _tunnel_reachable(ip):
                return True
            if attempt < config.TUNNEL_CHECK_ATTEMPTS - 1:
                time.sleep(config.TUNNEL_CHECK_RETRY_DELAY)
        return False

    def _vpn_assign_one(self, nic, node):
        """嘗試把 nic 連到 node。回傳 (ok, tunnel_ok, assigned_ip)。

        - ok: session 是否建立 (account_connect 成功)。
        - tunnel_ok: 資料路徑是否可達 (True/False)，未測過給 None。
        - assigned_ip: tunnel 本機 IP (成功時非 None)。
        """
        if not self._vpn_connect_only(nic, node):
            return (False, None, None)
        ip = _ps_ipv4(nic)
        if ip is None:
            self._vpn_post(self._vpn_log, "     ! NIC 未取得 IP")
            self.vpn_se.account_disconnect(nic)
            return (True, None, None)
        self._vpn_post(self._vpn_log, f"     + 已連線，指派 IP {ip}")
        if self._vpn_tunnel_ok(ip):
            self._vpn_post(self._vpn_log, f"     + tunnel 可通 ({ip})")
            return (True, True, ip)
        self._vpn_post(self._vpn_log, "     ! tunnel 不通")
        self.vpn_se.account_disconnect(nic)
        return (True, False, ip)

    def _vpn_after_assign(self, result):
        self.vpn_assigning = False
        result = result or {}
        results = result.get("results", {})
        outcomes = result.get("outcomes", [])
        now = time.time()
        # 記錄連線結果 (成功/失敗、tunnel 是否可達)
        for node_ip, ok, tunnel_ok in outcomes:
            vpn_history.record_connect(self.vpn_history, node_ip, ok, tunnel_ok)
        # 成功的網卡註冊 session state，供監視器追蹤
        for nic, info in results.items():
            node = info["node"]
            self._vpn_log(f"  ✓ {nic}: {node.hostname} {node.ip}:{node.port} ({node.country_long})")
            self.vpn_session_state[nic] = {
                "node_ip": node.ip,
                "ip": info["ip"],
                "started_at": now,
                "unhealthy_streak": 0,
            }
        if outcomes or results:
            vpn_history.save_history(config.VPN_HISTORY_FILE, self.vpn_history)
        self._vpn_render_nodes(self.vpn_candidates)
        self.vpn_refresh_nics()

    # --------------------------------------------------------- 會話監視器
    def _vpn_monitor_tick(self):
        if self.vpn_assigning:
            return
        nics = [nic for nic, st in self.vpn_session_state.items() if st.get("ip")]
        if not nics:
            return

        def work():
            results = {}
            for nic in nics:
                st = self.vpn_session_state.get(nic)
                if not st:
                    continue
                try:
                    connected = self.vpn_se.is_connected(nic)
                except Exception:
                    connected = False
                reachable = None
                if connected:
                    try:
                        reachable = _tunnel_reachable(
                            st["ip"], timeout=config.MONITOR_TUNNEL_TIMEOUT,
                        )
                    except Exception:
                        reachable = False
                results[nic] = (connected, reachable)
            return results

        self._vpn_run_bg(work, done=self._vpn_monitor_on_results)

    def _vpn_monitor_on_results(self, results):
        now = time.time()
        kicked = []  # (nic, node_ip)
        for nic, (connected, reachable) in (results or {}).items():
            st = self.vpn_session_state.get(nic)
            if not st:
                continue
            if not connected:
                self._vpn_log(f"  ! {nic} 已離線，判定中斷")
                self._vpn_record_session_end(st, now)
                kicked.append((nic, st["node_ip"]))
            elif reachable is False:
                st["unhealthy_streak"] += 1
                if st["unhealthy_streak"] >= config.TUNNEL_DEAD_THRESHOLD:
                    self._vpn_log(
                        f"  ! {nic} 假連線 (tunnel 連續 {st['unhealthy_streak']} 次不可達)"
                    )
                    self._vpn_record_session_end(st, now)
                    kicked.append((nic, st["node_ip"]))
            else:
                st["unhealthy_streak"] = 0
        if kicked:
            vpn_history.save_history(config.VPN_HISTORY_FILE, self.vpn_history)
            self._vpn_auto_reconnect(kicked)

    def _vpn_record_session_end(self, st, now):
        duration = max(0, int(now - st["started_at"]))
        vpn_history.record_session(self.vpn_history, st["node_ip"], duration)
        vpn_history.record_disconnect(self.vpn_history, st["node_ip"])

    def _vpn_auto_reconnect(self, kicked):
        nics = [nic for nic, _ in kicked]
        exclude_ips = {ip for _, ip in kicked}
        for nic in nics:
            self.vpn_session_state.pop(nic, None)
        self._vpn_log(f"自動換線: {', '.join(nics)}")
        self.vpn_assigning = True
        self._vpn_run_bg(
            lambda: self._vpn_assign_nics(nics, exclude_ips=exclude_ips),
            done=self._vpn_after_assign,
        )

    # --------------------------------------------------------- 節點面板
    def vpn_fetch_nodes(self):
        self._vpn_log("抓取節點列表…")
        self._vpn_run_bg(vpngate.fetch_nodes, done=self._vpn_on_nodes)

    def _vpn_on_nodes(self, nodes):
        nodes = nodes or []
        for n in nodes:
            vpn_history.upsert_node(self.vpn_history, n)
        vpn_history.prune(self.vpn_history)
        vpn_history.save_history(config.VPN_HISTORY_FILE, self.vpn_history)
        self._vpn_rebuild_all_nodes()
        self._vpn_fill_countries()
        self.vpn_apply_filters()
        self._vpn_log(f"抓到 {len(nodes)} 個節點，節點池累計 {len(self.vpn_all_nodes)} 個")

    def _vpn_rebuild_all_nodes(self):
        nodes = self.vpn_history.get("nodes", {})
        if not isinstance(nodes, dict):
            nodes = {}
        self.vpn_all_nodes = [
            vpngate.node_from_record(rec)
            for rec in nodes.values()
            if isinstance(rec, dict) and rec.get("ip")
        ]

    def _vpn_fill_countries(self):
        self.list_vpn_countries.clear()
        seen = []
        for n in sorted(self.vpn_all_nodes, key=lambda x: x.country_long):
            if n.country_long not in seen:
                seen.append(n.country_long)
        for c in seen:
            self.list_vpn_countries.addItem(c)

    def _vpn_selected_countries(self):
        return [item.text() for item in self.list_vpn_countries.selectedItems()]

    def vpn_apply_filters(self):
        if not self.vpn_all_nodes:
            self._vpn_log("無節點資料，請先抓取")
            return
        min_speed = self.spin_vpn_min_speed.value() * 1_000_000
        self.vpn_candidates = vpngate.rank_nodes(
            self.vpn_all_nodes,
            min_speed=min_speed,
            exclude_public=self.chk_vpn_excl_public.isChecked(),
            exclude_port_443=self.chk_vpn_excl_443.isChecked(),
            countries=self._vpn_selected_countries(),
        )
        # 以穩定度排序 (取代官方 Score 排序)
        self.vpn_candidates = vpngate.rank_by_stability(
            self.vpn_candidates, self.vpn_history,
        )
        self._vpn_render_nodes(self.vpn_candidates)
        self._vpn_log(f"篩選後 {len(self.vpn_candidates)} 個候選節點")

    def _vpn_render_nodes(self, nodes):
        self.vpn_row_nodes = nodes
        self.table_vpn_nodes.setRowCount(0)
        for n in nodes:
            rec = self._vpn_rec(n)
            attempts = rec.get("connect_attempts", 0)
            successes = rec.get("connect_successes", 0)
            session_count = rec.get("session_count", 0)
            total_sec = rec.get("total_connected_seconds", 0)
            last_seen = rec.get("last_seen", 0)

            success_s = f"{successes}/{attempts}" if attempts else "-"
            avg_s = _fmt_duration(total_sec / session_count) if session_count else "-"
            last_seen_s = (
                time.strftime("%m-%d %H:%M", time.localtime(last_seen))
                if last_seen else "-"
            )

            row = self.table_vpn_nodes.rowCount()
            self.table_vpn_nodes.insertRow(row)
            values = [
                n.hostname,
                n.ip,
                str(n.port),
                f"{vpn_history.stability(rec):.2f}",
                success_s,
                avg_s,
                str(rec.get("disconnect_count", 0)),
                str(n.score),
                f"{n.ping_ms}ms",
                f"{n.speed_bps / 1e6:.0f}M",
                n.country_long,
                str(rec.get("consecutive_failures", 0)),
                last_seen_s,
            ]
            for col, val in enumerate(values):
                self.table_vpn_nodes.setItem(row, col, QTableWidgetItem(val))
