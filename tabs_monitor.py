# -*- coding: utf-8 -*-
"""監控分頁/右鍵選單/服務控制 mixin (自 IntegratedApp.MainWindow 抽出)
"""

import time
import logging
import ctypes
import os
import json
from datetime import datetime

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout,
                             QHBoxLayout, QTableWidget, QTableWidgetItem,
                             QPushButton, QLabel, QGroupBox, QSpinBox, QTextEdit,
                             QListWidget, QSplitter, QMessageBox, QHeaderView,
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr, SUPPORTED_LANGS
import network_utils
import proxy_core
import secure_config
import rule_utils
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol


class MonitorTabMixin:
    def setup_monitor_tab(self):
        layout = QVBoxLayout(self.tab_monitor)
        cols = ["Time", "Process", "PID", "Destination", "Info"]
        self.tree_traffic = QTableWidget()
        self.tree_traffic.setColumnCount(len(cols))
        self._reg("headers", self.tree_traffic, cols)   # [i18n] 表頭也走語系檔
        # 短欄位依內容自動收合，Process(變動文字)才伸展；Info 為 Proxy(TCP) 等短文字
        self.tree_traffic.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_traffic.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree_traffic.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_traffic.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_traffic.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.tree_traffic.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tree_traffic.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_traffic.customContextMenuRequested.connect(self.show_traffic_menu)
        layout.addWidget(self.tree_traffic)
        
        btn_clear = QPushButton("")
        self._reg("text", btn_clear, "清除記錄")
        btn_clear.clicked.connect(lambda: self.tree_traffic.setRowCount(0))
        layout.addWidget(btn_clear)

    # (其他邏輯函式，如 add_hub_port, refresh_hub_table 等，保持不變)
    def show_rule_menu(self, pos):
        row = self.table_rules.rowAt(pos.y())
        if row < 0: return
        self.table_rules.selectRow(row)
        menu = QMenu()
        act_edit = QAction(self.t("編輯規則"), self)
        act_edit.triggered.connect(lambda: self.on_rule_double_click(row, 0))
        act_del = QAction(self.t("刪除規則"), self)
        act_del.triggered.connect(self.del_rule)
        menu.addAction(act_edit)
        menu.addAction(act_del)
        menu.exec(self.table_rules.viewport().mapToGlobal(pos))

    def show_proxy_menu(self, pos):
        row = self.table_custom_proxies.rowAt(pos.y())
        if row < 0: return
        self.table_custom_proxies.selectRow(row)
        menu = QMenu()
        act_edit = QAction(self.t("編輯代理"), self)
        act_edit.triggered.connect(lambda: self.on_proxy_double_click(row, 0))
        act_del = QAction(self.t("刪除代理"), self)
        act_del.triggered.connect(self.del_custom_proxy)
        menu.addAction(act_edit)
        menu.addAction(act_del)
        menu.exec(self.table_custom_proxies.viewport().mapToGlobal(pos))

    def show_traffic_menu(self, pos):
        item = self.tree_traffic.itemAt(pos)
        if not item: return
        row = item.row()
        pid = self.tree_traffic.item(row, 2).text()
        proc = self.tree_traffic.item(row, 1).text()
        menu = QMenu()
        act_pid = QAction(self.t("為 PID {pid} 新增規則").format(pid=pid), self)
        act_pid.triggered.connect(lambda: self.quick_add_rule(pid, True))
        act_proc = QAction(self.t("為 {proc} 新增規則").format(proc=proc), self)
        act_proc.triggered.connect(lambda: self.quick_add_rule(proc, False))
        menu.addAction(act_pid)
        menu.addAction(act_proc)
        menu.exec(self.tree_traffic.viewport().mapToGlobal(pos))

    def quick_add_rule(self, target, is_pid):
        self.tabs.setCurrentIndex(1)
        self.ent_target.setText(str(target))
        if is_pid: self.rb_pid.setChecked(True)
        else: self.rb_name.setChecked(True)

# [新增] 強制重刷規則到 DLL (解決啟動後規則不生效的問題)
    def _resolve_proxy(self, rule):
        """把規則的代理參照解析成 (proxy_id, 顯示文字)。

        優先用穩定識別 proxy_name ("custom:名稱" / "hub:端口", 新格式;
        舊版無前綴值向下相容 — custom 先、hub 後);再退回比對顯示字串。
        代理已被刪除時回傳 (0, 原字串), 讓呼叫端決定後續 (直連/轉換)。
        """
        proxy_name = rule.get('proxy_name', '')
        if proxy_name:
            if proxy_name.startswith('custom:'):
                want = proxy_name[7:]
                for p in self.custom_proxies:
                    if p['name'] == want:
                        return p['id'], f"[Custom] {p['name']}"
            elif proxy_name.startswith('hub:'):
                want = proxy_name[4:]
                for port, pid in self.hub_proxy_map.items():
                    if str(port) == want:
                        return pid, f"[Hub] Local Port {port}"
            else:
                # 舊版無前綴: 沿用舊行為 (custom 名稱先比, 再比 hub 端口)
                for p in self.custom_proxies:
                    if p['name'] == proxy_name:
                        return p['id'], f"[Custom] {p['name']}"
                for port, pid in self.hub_proxy_map.items():
                    if str(port) == proxy_name:
                        return pid, f"[Hub] Local Port {port}"
        proxy_text = rule.get('proxy', '')
        idx = self.combo_proxy.findText(proxy_text)
        if idx >= 0:
            return int(self.combo_proxy.itemData(idx) or 0), proxy_text
        return 0, proxy_text

    def _rule_proxy_id(self, rule):
        """規則引用的代理 ID。

        快路徑: 記錄的最後已知 proxy_id 仍然有效 (該代理存在且 ID 相同)
        就直接用 — 特別是「代理已刪除」情境, 名稱解析已落空, 但重刷邏輯
        需要靠這個舊 ID 找出受影響的規則。
        """
        last = rule.get('proxy_id')
        if last:
            for p in self.custom_proxies:
                if p['id'] == last:
                    return last
            for _port, pid in self.hub_proxy_map.items():
                if pid == last:
                    return last
        return self._resolve_proxy(rule)[0]

    def reapply_all_rules(self, only_proxy_id=None):
        if not self.rules:
            return

        # 若指定 only_proxy_id，只重刷引用該代理的規則（例如刪除代理後；
        # 此時名稱解析已失效, 靠 rule 內記錄的最後已知 proxy_id 找出目標）
        if only_proxy_id is not None:
            target_rules = [r for r in self.rules if self._rule_proxy_id(r) == only_proxy_id]
        else:
            target_rules = self.rules
        if not target_rules:
            return

        self.append_log("正在重新套用所有規則以確保生效...")

        # 為了避免在迭代時修改列表導致問題，我們建立一個暫存的新列表
        refreshed_rules = []

        for r in self.rules:
            if r not in target_rules:
                refreshed_rules.append(r)
                continue

            old_id = r['id']

            # 1. 先嘗試刪除舊的 (如果存在)
            # 注意：如果 DLL 在 Start 時清空了內部列表，這步可能無效但無害
            self.bridge.delete_rule(old_id)

            # 2. 重新解析 Proxy ID (ID 可能在重啟/代理重刷後變更)
            proxy_id, _display = self._resolve_proxy(r)

            # [Fixed] 引用的代理已不存在: 核心對「PROXY 動作 + proxy_id=0」
            # 的行為是直接斷線 (黑洞), 因此把規則轉為直連並明確告知,
            # 而不是讓它指向失效 ID 或以 PROXY+0 重灌
            if proxy_id == 0 and r.get('proxy_id') and self._rule_action_idx(r) == 0:
                r['action_key'] = 1
                r['action'] = 'DIRECT (直連)'
                r['proxy_name'] = ''
                r['proxy'] = self.t("未指定 (Fallback to Direct)")
                self.append_log(f"規則 '{r['target']}' 引用的代理已不存在，已轉為直連")

            r['proxy_id'] = proxy_id

            # 3. 呼叫 DLL 加入規則 (統一入口,這會觸發 UpdateFilter)
            new_rid = self.bridge.add_rule_ex(
                r['type'], r['target'], r.get('hosts', '*'), r.get('ports', '*'),
                r.get('proto', 'BOTH'), self._rule_action_idx(r), int(proxy_id))

            # 4. 更新規則資料中的 ID
            if new_rid > 0:
                r['id'] = new_rid
                refreshed_rules.append(r)
                logging.debug(f"規則 '{r['target']}' 已重刷，新 ID: {new_rid}")
            else:
                self.append_log(f"[錯誤] 無法重刷規則: {r['target']}")
                # 即使失敗也保留舊資料，避免介面清空
                refreshed_rules.append(r)

        # 更新記憶體中的列表
        self.rules = refreshed_rules
        # 更新介面上的 ID 顯示
        self.refresh_rules_table()
        self.append_log(f"已重新套用 {len(self.rules)} 條規則。")

    def toggle_redirector_service(self):
        # 檢查按鈕目前的狀態 (因為是 checkable，點擊後狀態已經改變)
        is_checked = self.btn_master_switch.isChecked()
        
        if is_checked:
            # === 嘗試啟動 ===
            if self.bridge.start():
                self.is_redirector_running = True
                self.update_service_status()
                logging.info("NetRedirector Started")
                
                # [關鍵修正] 啟動成功後，立即重刷所有規則
                # 這會強制 DLL 重新產生 WinDivert Filter String
                self.reapply_all_rules()
                
            else:
                # 啟動失敗，將按鈕彈回
                self.btn_master_switch.setChecked(False)
                QMessageBox.critical(self, self.t("錯誤"), self.t("無法啟動驅動，請確認管理員權限或驅動檔案是否存在。"))
        else:
            # === 停止服務 ===
            self.bridge.stop()
            self.is_redirector_running = False
            self.update_service_status()
            logging.info("NetRedirector Stopped")

