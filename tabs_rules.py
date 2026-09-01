# -*- coding: utf-8 -*-
"""規則分頁 mixin (自 IntegratedApp.MainWindow 抽出)
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


class RulesTabMixin:
    def setup_rules_tab(self):
        layout = QVBoxLayout(self.tab_rules)
        self.group_rule_form = QGroupBox("")
        form_layout = QVBoxLayout()
        
        row1 = QHBoxLayout()
        self.bg_rule_type = QButtonGroup()
        self.rb_name = QRadioButton("")
        self._reg("text", self.rb_name, "Process Name")   # [i18n] 表單標籤
        self.rb_name.setChecked(True)
        self.rb_pid = QRadioButton("PID")
        self._reg("text", self.rb_pid, "PID")
        self.bg_rule_type.addButton(self.rb_name, 0)
        self.bg_rule_type.addButton(self.rb_pid, 1)
        self.ent_target = QLineEdit()
        self._reg("placeholder", self.ent_target, "例如: chrome.*;Game*.exe ，或 PID 1234")
        row1.addWidget(self.rb_name)
        row1.addWidget(self.rb_pid)
        lbl_target = QLabel("")
        self._reg("text", lbl_target, "目標:")
        row1.addWidget(lbl_target)
        row1.addWidget(self.ent_target)
        form_layout.addLayout(row1)
        
        row2 = QHBoxLayout()
        self.ent_hosts = QLineEdit()
        self._reg("placeholder", self.ent_hosts, "IP/域名 (預設 *) 例: 8.8.8.8;*.google.com;192.168.*.*")
        self.ent_hosts.setText("*")
        self.ent_hosts.setFixedWidth(280)
        self.ent_ports = QLineEdit()
        self._reg("placeholder", self.ent_ports, "Port (預設 *) 例: 443;1000-2000")
        self.ent_ports.setText("*")
        self.ent_ports.setFixedWidth(100)
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["BOTH", "TCP", "UDP"])
        self.combo_proto.setFixedWidth(80)
        lbl_hosts = QLabel("")
        self._reg("text", lbl_hosts, "Hosts:")   # [i18n] 表單標籤
        row2.addWidget(lbl_hosts)
        row2.addWidget(self.ent_hosts)
        lbl_ports = QLabel("")
        self._reg("text", lbl_ports, "Ports:")
        row2.addWidget(lbl_ports)
        row2.addWidget(self.ent_ports)
        lbl_proto = QLabel("")
        self._reg("text", lbl_proto, "Proto:")
        row2.addWidget(lbl_proto)
        row2.addWidget(self.combo_proto)
        row2.addStretch()
        form_layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.combo_action = QComboBox()
        self._reg("combo", self.combo_action, ["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"])
        self.combo_proxy = QComboBox()
        self.refresh_proxy_combobox()
        self.btn_rule_action = QPushButton("")
        self.btn_rule_action.clicked.connect(self.save_rule_action)
        self.btn_rule_cancel = QPushButton("")
        self._reg("text", self.btn_rule_cancel, "取消修改")
        self.btn_rule_cancel.clicked.connect(self.cancel_rule_edit)
        self.btn_rule_cancel.hide()
        lbl_action = QLabel("")
        self._reg("text", lbl_action, "動作:")
        lbl_proxy = QLabel("")
        self._reg("text", lbl_proxy, "指定代理:")
        row3.addWidget(lbl_action)
        row3.addWidget(self.combo_action)
        row3.addSpacing(20)
        row3.addWidget(lbl_proxy)
        row3.addWidget(self.combo_proxy)
        row3.addStretch()
        row3.addWidget(self.btn_rule_action)
        row3.addWidget(self.btn_rule_cancel)
        form_layout.addLayout(row3)
        
        self.group_rule_form.setLayout(form_layout)
        layout.addWidget(self.group_rule_form)
        
        self.table_rules = QTableWidget()
        cols = ["ID", "類型", "目標", "Hosts", "Ports", "Proto", "動作", "代理"]
        self.table_rules.setColumnCount(len(cols))
        self._reg("headers", self.table_rules, cols)
        # 短欄位依內容自動收合，目標/代理(變動文字)才伸展
        self.table_rules.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table_rules.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.table_rules.setColumnHidden(0, True) 
        self.table_rules.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows) 
        self.table_rules.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) 
        self.table_rules.cellDoubleClicked.connect(self.on_rule_double_click)
        self.table_rules.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_rules.customContextMenuRequested.connect(self.show_rule_menu)
        layout.addWidget(self.table_rules)
        
        btn_row = QHBoxLayout()
        btn_del = QPushButton("")
        self._reg("text", btn_del, "刪除選中規則")
        btn_del.clicked.connect(self.del_rule)
        lbl_hint = QLabel("")
        self._reg("text", lbl_hint, "提示：雙擊規則列可編輯，或按右鍵開啟選單")
        lbl_hint.setStyleSheet("color: gray;")
        btn_row.addWidget(btn_del)
        btn_row.addStretch()
        btn_row.addWidget(lbl_hint)
        layout.addLayout(btn_row)

    def on_rule_double_click(self, row, col):
        if row < 0: return
        rule_id = int(self.table_rules.item(row, 0).text())
        rule_data = next((r for r in self.rules if r['id'] == rule_id), None)
        if not rule_data: return

        self.editing_rule_id = rule_id

        self.ent_target.setText(rule_data['target'])
        self.ent_hosts.setText(rule_data.get('hosts', '*'))
        self.ent_ports.setText(rule_data.get('ports', '*'))
        if rule_data['type'] == 'PID': self.rb_pid.setChecked(True)
        else: self.rb_name.setChecked(True)
        idx_proto = self.combo_proto.findText(rule_data.get('proto', 'BOTH'))
        if idx_proto >= 0: self.combo_proto.setCurrentIndex(idx_proto)
        self.combo_action.setCurrentIndex(self._rule_action_idx(rule_data))
        current_proxy_text = rule_data['proxy']
        idx_proxy = self.combo_proxy.findText(current_proxy_text)
        if idx_proxy >= 0: self.combo_proxy.setCurrentIndex(idx_proxy)
        else: self.combo_proxy.setCurrentIndex(0)
        self.update_form_titles()

    def _rule_action_idx(self, rule_data):
        key = rule_data.get('action_key')
        if key is not None:
            return int(key)
        a = rule_data.get('action', '')
        if "DIRECT" in a: return 1
        if "BLOCK" in a: return 2
        return 0

    def _action_display(self, rule_data):
        return self.t(["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"][self._rule_action_idx(rule_data)])

    def cancel_rule_edit(self):
        self.editing_rule_id = None
        self.ent_target.clear()
        self.ent_hosts.setText("*")
        self.ent_ports.setText("*")
        self.combo_proxy.setCurrentIndex(0)
        self.combo_action.setCurrentIndex(0)
        self.update_form_titles()

    def _proxy_stable_name(self, proxy_id):
        """從 combo 的 itemData (代理 ID) 反推穩定識別, 加命名空間前綴:
        自訂代理 → "custom:名稱", Hub → "hub:端口"。前綴避免「自訂代理名稱
        恰為端口數字」時劫走 Hub 規則;與顯示文字 (可被翻譯) 脫鉤。
        舊版 config 的無前綴值由 _resolve_proxy 向下相容。"""
        if not proxy_id:
            return ""
        for p in self.custom_proxies:
            if p['id'] == proxy_id:
                return f"custom:{p['name']}"
        for port, pid in self.hub_proxy_map.items():
            if pid == proxy_id:
                return f"hub:{port}"
        return ""

    def save_rule_action(self):
        # [Fixed] 正規化全形星號 (U+FF0A) 為半形，避免中文輸入法產生的規則永不匹配
        target = rule_utils.normalize_rule_target(self.ent_target.text())
        if not target: return
        hosts = rule_utils.normalize_rule_pattern(self.ent_hosts.text())
        ports = rule_utils.normalize_rule_pattern(self.ent_ports.text())
        proto_str = self.combo_proto.currentText()
        is_pid = self.rb_pid.isChecked()
        if is_pid and not (target.isascii() and target.isdigit()):
            # [Fixed] isascii 檔掉全形數字 ('１２３') 與上標數字 ('²') —
            # isdigit() 對它們為 True 但 int() 可能抛 ValueError
            QMessageBox.warning(self, self.t("錯誤"), self.t("PID 需為數字"))
            return
        action_idx = self.combo_action.currentIndex()
        action_text = self.combo_action.currentText()
        pid_proxy = int(self.combo_proxy.currentData() or 0)
        proxy_text = self.combo_proxy.currentText()
        proxy_name = self._proxy_stable_name(pid_proxy)
        was_edit = self.editing_rule_id is not None

        # [改進] 編輯規則時優先「原地更新」(EditRuleWithProxy 保留相同 ID)，
        # 避免規則 ID 跳動；僅「PID 規則」或「名稱/PID 類型切換」才需刪除重建
        # (C 核心的 EditRuleWithProxy 不處理 target_pid 欄位)
        rid = 0
        if was_edit:
            old_rule = next((r for r in self.rules if r['id'] == self.editing_rule_id), None)
            old_is_pid = bool(old_rule and old_rule.get('type') == 'PID')

            if not is_pid and not old_is_pid:
                if self.bridge.edit_rule_ex(self.editing_rule_id, target, hosts, ports, proto_str, action_idx, pid_proxy):
                    rid = self.editing_rule_id  # ID 不變，原地生效
                else:
                    # 原地更新失敗 → 回退為刪除+重建
                    self.bridge.delete_rule(self.editing_rule_id)
                    self.rules = [r for r in self.rules if r['id'] != self.editing_rule_id]
            else:
                self.bridge.delete_rule(self.editing_rule_id)
                self.rules = [r for r in self.rules if r['id'] != self.editing_rule_id]
                logging.info(f"正在更新規則 ID {self.editing_rule_id} -> 先行刪除")

        if rid == 0:
            rid = self.bridge.add_rule_ex('PID' if is_pid else 'Name', target, hosts, ports, proto_str, action_idx, pid_proxy)

        if rid > 0:
            new_rule = {
                'id': rid,
                'type': 'PID' if is_pid else 'Name',
                'target': target,
                'hosts': hosts,
                'ports': ports,
                'proto': proto_str,
                'action': action_text,
                'action_key': action_idx,
                'proxy': proxy_text,
                'proxy_name': proxy_name,
                'proxy_id': pid_proxy   # [Fixed] 最後已知 ID: 供刪除代理時重刷規則
            }
            if was_edit and rid == self.editing_rule_id:
                # 原地更新：取代對應項目，保持 ID 不變
                self.rules = [new_rule if r['id'] == rid else r for r in self.rules]
            else:
                self.rules.append(new_rule)
            self.refresh_rules_table()
            self.cancel_rule_edit()
            self.append_log(f"規則已{'更新' if was_edit else '新增'} (ID: {rid})")
        else:
            QMessageBox.warning(self, self.t("失敗"), self.t("驅動返回錯誤，規則添加失敗。"))

    def del_rule(self):
        row = self.table_rules.currentRow()
        if row < 0: return
        rid = int(self.table_rules.item(row, 0).text())
        self.bridge.delete_rule(rid)
        self.rules = [r for r in self.rules if r['id'] != rid]
        self.refresh_rules_table()

    def refresh_rules_table(self):
        self.table_rules.setRowCount(0)
        for r in self.rules:
            row = self.table_rules.rowCount()
            self.table_rules.insertRow(row)
            self.table_rules.setItem(row, 0, QTableWidgetItem(str(r['id'])))
            self.table_rules.setItem(row, 1, QTableWidgetItem(r['type']))
            self.table_rules.setItem(row, 2, QTableWidgetItem(r['target']))
            self.table_rules.setItem(row, 3, QTableWidgetItem(r.get('hosts', '*')))
            self.table_rules.setItem(row, 4, QTableWidgetItem(r.get('ports', '*')))
            self.table_rules.setItem(row, 5, QTableWidgetItem(r.get('proto', 'BOTH')))
            self.table_rules.setItem(row, 6, QTableWidgetItem(self._action_display(r)))
            self.table_rules.setItem(row, 7, QTableWidgetItem(r['proxy']))

