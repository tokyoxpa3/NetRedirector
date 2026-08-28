# -*- coding: utf-8 -*-
"""VPN Gate 節點派發分頁 mixin (自 vpngate-auto-assign 融入)

左側: SoftEther 虛擬網卡清單 (狀態/伺服器) + 選取後一鍵上線。
右側: VPN Gate 節點清單 + 篩選 (排除 public-*、port 443、最低速度、國家)。

所有慢速操作 (vpncmd、抓節點、連線) 都在背景執行緒執行，結果透過
queue 送回 UI 執行緒 (QTimer 輪詢)，避免凍結主執行緒。
"""

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
import softether


_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _ps_ipv4(interface_alias):
    """回傳 Windows 介面的 IPv4 位址，找不到回傳 None。"""
    try:
        out = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                f"(Get-NetIPAddress -InterfaceAlias '{interface_alias}' "
                "-AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress",
            ],
            capture_output=True,
            timeout=30,
            creationflags=_CREATE_NO_WINDOW,
        )
        text = out.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    for ln in lines:
        try:
            ipaddress.IPv4Address(ln)
            return ln
        except ValueError:
            continue
    return None


def _tunnel_reachable(source_ip, target="1.1.1.1", port=443):
    """綁定 source_ip 連 1.1.1.1:443 驗證 tunnel 有實際轉發流量。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.bind((source_ip, 0))
        sock.connect((target, port))
        sock.close()
        return True
    except Exception:
        return False


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
        nic_btns.addWidget(btn_refresh)
        nic_btns.addWidget(btn_connect)
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
        self.table_vpn_nodes.setColumnCount(8)
        self._reg("headers", self.table_vpn_nodes,
                  ["主機名", "IP", "Port", "Score", "Ping", "速度", "國家", "失敗"])
        # 短數值欄位依內容自動收合 (IP/Port/Score/Ping/速度/失敗)，主機名與國家等長文字才伸展
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table_vpn_nodes.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        self.table_vpn_nodes.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_vpn_nodes.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        right_layout.addWidget(self.table_vpn_nodes, 1)

        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

        # ---------- 背景執行緒 → UI 佇列 ----------
        self.vpn_queue = queue.Queue()
        self.vpn_se = softether.SoftEtherClient()
        self.vpn_all_nodes = []
        self.vpn_candidates = []
        self.vpn_fail_count = {}  # ip -> 連續失敗次數，成功後歸零
        self.vpn_timer = QTimer()
        self.vpn_timer.timeout.connect(self._vpn_poll_queue)
        self.vpn_timer.start(100)

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
        self._vpn_run_bg(lambda: self._vpn_assign_nics(offline), done=self._vpn_after_assign)

    def _vpn_assign_nics(self, nics):
        results = {}
        failed = self.vpn_fail_count
        used_ips = self._vpn_used_server_ips(exclude=set(nics))
        # 失敗次數高的排到最後，避免一直重試有問題的節點
        candidates = sorted(
            self.vpn_candidates,
            key=lambda n: (failed.get(n.ip, 0), -n.score),
        )
        cursor = 0
        max_attempts = 10
        for nic in nics:
            self._vpn_post(self._vpn_log, f"[{nic}] 開始指派…")
            assigned = False
            attempts = 0
            while not assigned and attempts < max_attempts and cursor < len(candidates):
                node = candidates[cursor]
                cursor += 1
                attempts += 1
                if node.ip in used_ips:
                    continue
                self._vpn_post(
                    self._vpn_log,
                    f"  -> 嘗試 {node.hostname} {node.ip}:{node.port} "
                    f"({node.country_long}, score={node.score})",
                )
                if self._vpn_assign_one(nic, node):
                    results[nic] = node
                    used_ips.add(node.ip)
                    failed.pop(node.ip, None)  # 連線成功，失敗計數歸零
                    assigned = True
                else:
                    failed[node.ip] = failed.get(node.ip, 0) + 1
            if not assigned:
                self._vpn_post(self._vpn_log, f"  X 無法為 {nic} 指派可用節點")
        return results

    def _vpn_assign_one(self, nic, node):
        self.vpn_se.account_disconnect(nic)
        self.vpn_se.account_set(nic, node.ip, node.port)
        self.vpn_se.account_set_anonymous(nic)
        self.vpn_se.account_connect(nic)
        if not _wait_connected(self.vpn_se, nic):
            self._vpn_post(self._vpn_log, "     ! session 未建立")
            return False
        ip = _ps_ipv4(f"{nic} - VPN Client")
        if ip is None:
            self._vpn_post(self._vpn_log, "     ! NIC 未取得 IP")
            self.vpn_se.account_disconnect(nic)
            return False
        self._vpn_post(self._vpn_log, f"     + 已連線，指派 IP {ip}")
        if _tunnel_reachable(ip):
            self._vpn_post(self._vpn_log, f"     + tunnel 可通 ({ip})")
            return True
        self._vpn_post(self._vpn_log, "     ! tunnel 不通")
        self.vpn_se.account_disconnect(nic)
        return False

    def _vpn_after_assign(self, results):
        for nic, node in (results or {}).items():
            self._vpn_log(f"  ✓ {nic}: {node.hostname} {node.ip}:{node.port} ({node.country_long})")
        self._vpn_render_nodes(self.vpn_candidates)
        self.vpn_refresh_nics()

    # --------------------------------------------------------- 節點面板
    def vpn_fetch_nodes(self):
        self._vpn_log("抓取節點列表…")
        self._vpn_run_bg(vpngate.fetch_nodes, done=self._vpn_on_nodes)

    def _vpn_on_nodes(self, nodes):
        self.vpn_all_nodes = nodes or []
        self._vpn_fill_countries()
        self.vpn_apply_filters()
        self._vpn_log(f"抓到 {len(self.vpn_all_nodes)} 個節點")

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
        self._vpn_render_nodes(self.vpn_candidates)
        self._vpn_log(f"篩選後 {len(self.vpn_candidates)} 個候選節點")

    def _vpn_render_nodes(self, nodes):
        self.table_vpn_nodes.setRowCount(0)
        for n in nodes:
            row = self.table_vpn_nodes.rowCount()
            self.table_vpn_nodes.insertRow(row)
            self.table_vpn_nodes.setItem(row, 0, QTableWidgetItem(n.hostname))
            self.table_vpn_nodes.setItem(row, 1, QTableWidgetItem(n.ip))
            self.table_vpn_nodes.setItem(row, 2, QTableWidgetItem(str(n.port)))
            self.table_vpn_nodes.setItem(row, 3, QTableWidgetItem(str(n.score)))
            self.table_vpn_nodes.setItem(row, 4, QTableWidgetItem(f"{n.ping_ms}ms"))
            self.table_vpn_nodes.setItem(row, 5, QTableWidgetItem(f"{n.speed_bps / 1e6:.0f}M"))
            self.table_vpn_nodes.setItem(row, 6, QTableWidgetItem(n.country_long))
            self.table_vpn_nodes.setItem(row, 7, QTableWidgetItem(str(self.vpn_fail_count.get(n.ip, 0))))
