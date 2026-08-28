# -*- coding: utf-8 -*-
"""Hub 分頁 mixin (自 IntegratedApp.MainWindow 抽出)
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
                             QTabWidget, QComboBox, QLineEdit, QRadioButton, QButtonGroup, QMenu,
                             QAbstractItemView)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr, SUPPORTED_LANGS
import network_utils
import proxy_core
import secure_config
import rule_utils
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol


class HubTabMixin:
    def setup_hub_tab(self):
        layout = QHBoxLayout(self.tab_hub)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QGroupBox("")
        self._reg("title", left_panel, "本地監聽端口")
        left_layout = QVBoxLayout()
        input_layout = QHBoxLayout()
        self.spin_hub_port = QSpinBox()
        self.spin_hub_port.setRange(1000, 65535)
        self.spin_hub_port.setValue(30678)
        btn_add = QPushButton("")
        self._reg("text", btn_add, "新增")
        btn_add.clicked.connect(self.add_hub_port)
        input_layout.addWidget(self.spin_hub_port)
        input_layout.addWidget(btn_add)
        
        self.list_hub_ports = QListWidget()
        # 多選:按住 Ctrl/Shift 可同時選取多個端口，啟動/刪除會作用於所有選中項
        self.list_hub_ports.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.list_hub_ports.itemClicked.connect(self.on_hub_port_selected)
        
        btn_del = QPushButton("")
        self._reg("text", btn_del, "刪除端口")
        btn_del.clicked.connect(self.del_hub_port)
        
        self.btn_apply_hub = QPushButton("")
        self._reg("text", self.btn_apply_hub, "啟動/重啟選中端口")
        self.btn_apply_hub.setStyleSheet("background-color: #4CAF50; color: white;")
        self.btn_apply_hub.clicked.connect(self.apply_hub_config)

        left_layout.addLayout(input_layout)
        left_layout.addWidget(self.list_hub_ports)
        left_layout.addWidget(self.btn_apply_hub)
        left_layout.addWidget(btn_del)
        left_panel.setLayout(left_layout)

        right_panel = QGroupBox("")
        self._reg("title", right_panel, "綁定出口網卡")
        right_layout = QVBoxLayout()
        self.lbl_hub_status = QLabel("")
        right_layout.addWidget(self.lbl_hub_status)
        
        filter_layout = QHBoxLayout()
        self.txt_hub_filter = QLineEdit()
        self._reg("placeholder", self.txt_hub_filter, "🔍 篩選介面 (例: VPN)")
        self.txt_hub_filter.textChanged.connect(self.refresh_hub_table) 
        
        btn_select_all_visible = QPushButton("")
        self._reg("text", btn_select_all_visible, "全選顯示項目")
        btn_select_all_visible.clicked.connect(self.on_hub_select_all_visible)
        
        filter_layout.addWidget(self.txt_hub_filter)
        filter_layout.addWidget(btn_select_all_visible)
        right_layout.addLayout(filter_layout)

        self.table_hub = QTableWidget()
        # 綁定表格僅供勾選，不允許編輯文字
        self.table_hub.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_hub.setColumnCount(5)
        self._reg("headers", self.table_hub, ["綁定", "介面名稱", "IP", "延遲", "負載"])
        # 短欄位依內容自動收合，介面名稱(變動文字)才伸展
        self.table_hub.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table_hub.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_hub.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_hub.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table_hub.setColumnWidth(3, 80)
        self.table_hub.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_hub.cellClicked.connect(self.on_hub_table_click)

        right_layout.addWidget(self.table_hub)
        right_panel.setLayout(right_layout)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    def add_hub_port(self):
        port = self.spin_hub_port.value()
        if port in self.port_config: return
        self.port_config[port] = []
        self.list_hub_ports.addItem(f"{port}")
        self.spin_hub_port.setValue(port + 1)
        self.sync_hub_proxy(port)

    def del_hub_port(self):
        items = self.list_hub_ports.selectedItems()
        if not items:
            item = self.list_hub_ports.currentItem()
            if item:
                items = [item]
        if not items:
            return
        ports = [int(it.text().split()[0]) for it in items]
        for port in ports:
            proxy_core.server_controller.stop_port(port)
            if port in self.port_config: del self.port_config[port]
            # [Fixed] 同步刪除 DLL 中的 Hub 代理設定，避免殘留幽靈代理
            # (sync_hub_proxy 曾對每個 Hub 端口呼叫 add_proxy 註冊代理)
            pid = self.hub_proxy_map.pop(port, None)
            if pid and hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
                try:
                    self.bridge.lib.NetRedirector_DeleteProxyConfig(pid)
                    self.append_log(f"已移除 Hub 端口 {port} 的 DLL 代理設定 (ID: {pid})")
                except Exception as e:
                    self.append_log(f"移除 Hub 端口代理設定失敗: {e}")
        # 從清單移除對應項目 (依實際 item 物件，避免索引位移問題)
        for it in items:
            row = self.list_hub_ports.row(it)
            if row >= 0:
                self.list_hub_ports.takeItem(row)
        self.selected_hub_port = None
        self.refresh_hub_table()
        self.refresh_proxy_combobox()

    def on_hub_port_selected(self, item):
        if not item: return
        self.selected_hub_port = int(item.text().split()[0])
        self.update_hub_status()
        self.refresh_hub_table()

    def selected_hub_ports(self):
        """回傳目前清單中被選取的所有端口 (依清單順序)。"""
        return [int(self.list_hub_ports.item(i).text().split()[0])
                for i in range(self.list_hub_ports.count())
                if self.list_hub_ports.item(i).isSelected()]

    def apply_hub_config(self):
        ports = self.selected_hub_ports()
        if not ports:
            # 無選取時沿用舊行為：以最後點選的端口為準
            if self.selected_hub_port:
                ports = [self.selected_hub_port]
            else:
                return
        for port in ports:
            interfaces = self.port_config.get(port, [])
            proxy_core.route_manager.update_port_binding(port, interfaces)
            success = proxy_core.server_controller.start_port(port)
            self.update_hub_list_item(port, success)
            if success:
                self.sync_hub_proxy(port)
                logging.info(f"Hub 端口 {port} 已啟動")

    def sync_hub_proxy(self, port):
        if port in self.hub_proxy_map: return
        pid = self.bridge.add_proxy("127.0.0.1", port, "", "", ProxyType.SOCKS5, f"Hub_Port_{port}")
        if pid > 0:
            self.hub_proxy_map[port] = pid
            self.refresh_proxy_combobox()

    def update_hub_list_item(self, port, is_running):
        for i in range(self.list_hub_ports.count()):
            item = self.list_hub_ports.item(i)
            if item.text().startswith(str(port)):
                status = self.t("(運行中)") if is_running else self.t("(失敗)")
                item.setText(f"{port} {status}")
                item.setForeground(QBrush(QColor("green") if is_running else QColor("red")))
                break

    def refresh_hub_table(self):
        scroll_pos = self.table_hub.verticalScrollBar().value()
        self.table_hub.setRowCount(0)
        if not self.selected_hub_port: return
        filter_keyword = self.txt_hub_filter.text().lower().strip()
        bound_list = self.port_config.get(self.selected_hub_port, [])
        all_interface_names = set(self.current_interfaces.keys()) | set(bound_list)
        sorted_names = sorted(list(all_interface_names),
                              key=lambda x: (0 if x in self.current_interfaces else 1, x))

        for name in sorted_names:
            if filter_keyword and filter_keyword not in name.lower(): continue
            row = self.table_hub.rowCount()
            self.table_hub.insertRow(row)
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Checked if name in bound_list else Qt.CheckState.Unchecked)
            self.table_hub.setItem(row, 0, chk)
            name_item = QTableWidgetItem(name)
            self.table_hub.setItem(row, 1, name_item)
            if name in self.current_interfaces:
                data = self.current_interfaces[name]
                self.table_hub.setItem(row, 2, QTableWidgetItem(data['ipv4']))
                lat_item = QTableWidgetItem(str(data['latency']) + " ms")
                if data['latency'] < 100: lat_item.setForeground(QBrush(QColor("#4CAF50")))
                elif data['latency'] < 300: lat_item.setForeground(QBrush(QColor("#FF9800")))
                else: lat_item.setForeground(QBrush(QColor("#F44336")))
                self.table_hub.setItem(row, 3, lat_item)
                active = proxy_core.route_manager.interfaces.get(name, {}).get('active_conns', 0)
                self.table_hub.setItem(row, 4, QTableWidgetItem(str(active)))
            else:
                name_item.setForeground(QBrush(QColor("gray")))
                offline_item = QTableWidgetItem(self.t("離線 (等待重連...)"))
                offline_item.setForeground(QBrush(QColor("gray")))
                self.table_hub.setItem(row, 2, offline_item)
                self.table_hub.setItem(row, 3, QTableWidgetItem("-"))
                self.table_hub.setItem(row, 4, QTableWidgetItem("0"))
        self.table_hub.verticalScrollBar().setValue(scroll_pos)

    def on_hub_select_all_visible(self):
        if not self.selected_hub_port: return
        current_bound = self.port_config.get(self.selected_hub_port, [])
        is_changed = False
        for row in range(self.table_hub.rowCount()):
            name_item = self.table_hub.item(row, 1)
            if not name_item: continue
            name = name_item.text()
            chk_item = self.table_hub.item(row, 0)
            if chk_item.checkState() != Qt.CheckState.Checked:
                chk_item.setCheckState(Qt.CheckState.Checked)
                if name not in current_bound:
                    current_bound.append(name)
                    is_changed = True
        if is_changed:
            self.port_config[self.selected_hub_port] = current_bound
            proxy_core.route_manager.update_port_binding(self.selected_hub_port, current_bound)
            self.append_log(f"已批次更新端口 {self.selected_hub_port} 的綁定介面")

    def on_hub_table_click(self, row, col):
        if not self.selected_hub_port: return
        name = self.table_hub.item(row, 1).text()
        chk_item = self.table_hub.item(row, 0)
        if col == 0:
            # 點到勾選框時 Qt 已自動切換狀態，直接讀取新狀態
            checked = (chk_item.checkState() == Qt.CheckState.Checked)
        else:
            # 點到其他欄位時改為手動切換勾選，達成「點整列即可勾選」
            checked = (chk_item.checkState() != Qt.CheckState.Checked)
            chk_item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        curr = self.port_config.get(self.selected_hub_port, [])
        if checked and name not in curr: curr.append(name)
        elif not checked and name in curr: curr.remove(name)
        self.port_config[self.selected_hub_port] = curr
        proxy_core.route_manager.update_port_binding(self.selected_hub_port, curr)

