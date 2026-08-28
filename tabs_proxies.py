# -*- coding: utf-8 -*-
"""代理分頁 mixin (自 IntegratedApp.MainWindow 抽出)
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
from app_helpers import check_proxy_connection  # [Fixed] test_all_proxies 需要
from NetRedirector import NetRedirectorWrapper, RuleAction, ProxyType, RuleProtocol


class ProxiesTabMixin:
    def setup_custom_proxy_tab(self):
        layout = QVBoxLayout(self.tab_proxies)
        self.group_proxy_form = QGroupBox("")
        grid = QGridLayout()
        
        self.ent_cp_name = QLineEdit()
        self._reg("placeholder", self.ent_cp_name, "名稱 (例: MyVPN)")
        self.combo_cp_type = QComboBox()
        self.combo_cp_type.addItems(["SOCKS5", "HTTP"])
        lbl_cp_name = QLabel("")
        self._reg("text", lbl_cp_name, "名稱:")
        lbl_cp_type = QLabel("")
        self._reg("text", lbl_cp_type, "類型:")
        grid.addWidget(lbl_cp_name, 0, 0)
        grid.addWidget(self.ent_cp_name, 0, 1)
        grid.addWidget(lbl_cp_type, 0, 2)
        grid.addWidget(self.combo_cp_type, 0, 3)
        
        self.ent_cp_ip = QLineEdit()
        self._reg("placeholder", self.ent_cp_ip, "IP 地址")
        self.ent_cp_port = QLineEdit()
        self._reg("placeholder", self.ent_cp_port, "Port")
        self.ent_cp_port.setFixedWidth(80)
        lbl_cp_iph = QLabel("")
        self._reg("text", lbl_cp_iph, "IP Host:")
        lbl_cp_port = QLabel("")
        self._reg("text", lbl_cp_port, "Port:")
        grid.addWidget(lbl_cp_iph, 1, 0)
        grid.addWidget(self.ent_cp_ip, 1, 1)
        grid.addWidget(lbl_cp_port, 1, 2)
        grid.addWidget(self.ent_cp_port, 1, 3)
        
        self.ent_cp_user = QLineEdit()
        self._reg("placeholder", self.ent_cp_user, "驗證帳號 (選填)")
        self.ent_cp_pass = QLineEdit()
        self._reg("placeholder", self.ent_cp_pass, "驗證密碼 (選填)")
        self.ent_cp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        lbl_cp_user = QLabel("")
        self._reg("text", lbl_cp_user, "User:")
        lbl_cp_pass = QLabel("")
        self._reg("text", lbl_cp_pass, "Pass:")
        grid.addWidget(lbl_cp_user, 2, 0)
        grid.addWidget(self.ent_cp_user, 2, 1)
        grid.addWidget(lbl_cp_pass, 2, 2)
        grid.addWidget(self.ent_cp_pass, 2, 3)
        
        btn_layout = QHBoxLayout()
        self.btn_proxy_save = QPushButton("")
        self.btn_proxy_save.clicked.connect(self.save_custom_proxy)
        self.btn_proxy_cancel = QPushButton("")
        self._reg("text", self.btn_proxy_cancel, "取消修改")
        self.btn_proxy_cancel.clicked.connect(self.cancel_proxy_edit)
        self.btn_proxy_cancel.hide()
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_proxy_cancel)
        btn_layout.addWidget(self.btn_proxy_save)
        grid.addLayout(btn_layout, 3, 0, 1, 4) 
        
        self.group_proxy_form.setLayout(grid)
        layout.addWidget(self.group_proxy_form)
        
        toolbar = QHBoxLayout()
        btn_test = QPushButton("")
        self._reg("text", btn_test, "測試所有代理連線 (Ping)")
        btn_test.clicked.connect(self.test_all_proxies)
        btn_del = QPushButton("")
        self._reg("text", btn_del, "刪除選中代理")
        btn_del.clicked.connect(self.del_custom_proxy)
        toolbar.addWidget(btn_test)
        toolbar.addWidget(btn_del)
        lbl_hint = QLabel("")
        self._reg("text", lbl_hint, "提示：雙擊代理列可編輯，或按右鍵開啟選單")
        lbl_hint.setStyleSheet("color: gray;")
        toolbar.addStretch()
        toolbar.addWidget(lbl_hint)
        layout.addLayout(toolbar)

        self.table_custom_proxies = QTableWidget()
        cols = ["ID", "名稱", "類型", "IP:Port", "驗證", "延遲"]
        self.table_custom_proxies.setColumnCount(len(cols))
        self._reg("headers", self.table_custom_proxies, cols)
        # 短欄位依內容自動收合，名稱(變動文字)才伸展
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table_custom_proxies.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table_custom_proxies.setColumnWidth(5, 200)
        self.table_custom_proxies.setColumnHidden(0, True)
        self.table_custom_proxies.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_custom_proxies.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table_custom_proxies.cellDoubleClicked.connect(self.on_proxy_double_click)
        self.table_custom_proxies.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_custom_proxies.customContextMenuRequested.connect(self.show_proxy_menu)
        layout.addWidget(self.table_custom_proxies)

    def refresh_proxy_combobox(self):
        current_data = self.combo_proxy.currentData()
        self.combo_proxy.clear()
        has_real_proxies = False
        sorted_hubs = sorted(self.hub_proxy_map.items())
        for port, pid in sorted_hubs:
            self.combo_proxy.addItem(f"[Hub] Local Port {port}", pid)
            has_real_proxies = True
        for p in self.custom_proxies:
            self.combo_proxy.addItem(f"[Custom] {p['name']}", p['id'])
            has_real_proxies = True
        if not has_real_proxies:
            # [i18n] 此文字僅供顯示;規則持久化靠 proxy_name,不受翻譯影響
            self.combo_proxy.addItem(self.t("未指定 (Fallback to Direct)"), 0)
        idx = self.combo_proxy.findData(current_data)
        if idx >= 0: self.combo_proxy.setCurrentIndex(idx)
        elif self.combo_proxy.count() > 0: self.combo_proxy.setCurrentIndex(0)

    def save_custom_proxy(self):
        name = self.ent_cp_name.text()
        ip = self.ent_cp_ip.text()
        port_str = self.ent_cp_port.text()
        user = self.ent_cp_user.text()
        pwd = self.ent_cp_pass.text()
        ptype_str = self.combo_cp_type.currentText()
        if not name or not ip or not port_str:
            QMessageBox.warning(self, self.t("警告"), self.t("名稱、IP 與 Port 為必填"))
            return
        try: port = int(port_str)
        except: return
        ptype = ProxyType.SOCKS5 if ptype_str == "SOCKS5" else ProxyType.HTTP

        # [根因修正] 編輯代理「原地更新」：EditProxyConfig 保留相同 proxy ID，
        # 已建立的規則仍指向同一 ID，新帳密立即對所有規則生效，不需重刷規則
        old_proxy_id = self.editing_proxy_id
        if old_proxy_id is not None:
            edit_fn = getattr(self.bridge.lib, 'NetRedirector_EditProxyConfig', None)
            if edit_fn is not None:
                old_name = next((p['name'] for p in self.custom_proxies if p['id'] == old_proxy_id), None)
                ok = edit_fn(
                    old_proxy_id,
                    ptype,
                    name.encode('utf-8'),
                    ip.encode('utf-8'),
                    port,
                    user.encode('utf-8'),
                    pwd.encode('utf-8'),
                    True  # enabled
                )
                if ok:
                    for p in self.custom_proxies:
                        if p['id'] == old_proxy_id:
                            p.update({'name': name, 'type': ptype_str, 'ip': ip, 'port': port, 'user': user, 'pass': pwd})
                    # [Fixed] 改名時同步置換引用此代理的規則 (新舊前綴與舊版
                    # 無前綴都要比對): 否則存檔後規則仍指向舊名稱, 下次啟動
                    # 代理解析落空 → 規則靜默退回直連
                    if old_name is not None and old_name != name:
                        new_ref = f"custom:{name}"
                        old_refs = (f"custom:{old_name}", old_name)
                        for r in self.rules:
                            if r.get('proxy_name') in old_refs:
                                r['proxy_name'] = new_ref
                                r['proxy'] = f"[Custom] {name}"
                        self.refresh_rules_table()
                        self.append_log(f"代理更名 {old_name} → {name}，已同步更新引用它的規則")
                    self.refresh_custom_proxy_table()
                    self.refresh_proxy_combobox()
                    self.cancel_proxy_edit()
                    self.append_log(f"自訂代理已更新 (ID 不變，立即生效): {name}")
                    return
                else:
                    QMessageBox.warning(self, self.t("失敗"), self.t("DLL 無法更新代理配置"))
                    return

            # 舊版 DLL 沒有 EditProxyConfig 的 fallback：刪除+重建（ID 會變，需重刷規則）
            if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
                self.bridge.lib.NetRedirector_DeleteProxyConfig(old_proxy_id)
            self.custom_proxies = [p for p in self.custom_proxies if p['id'] != old_proxy_id]

        pid = self.bridge.add_proxy(ip, port, user, pwd, ptype, name)
        if pid > 0:
            self.custom_proxies.append({
                'id': pid,
                'name': name,
                'type': ptype_str,
                'ip': ip,
                'port': port,
                'user': user,
                'pass': pwd,
                'latency': '-'
            })
            self.refresh_custom_proxy_table()
            self.refresh_proxy_combobox()
            self.cancel_proxy_edit()
            self.append_log(f"自訂代理已新增: {name}")
            # 只有 fallback 刪除+重建路徑才需要重刷引用舊 ID 的規則
            if old_proxy_id is not None and pid != old_proxy_id:
                self.append_log(f"代理 ID 已變更 ({old_proxy_id} -> {pid})，重刷引用該代理的規則...")
                self.reapply_all_rules(only_proxy_id=old_proxy_id)
        else:
            QMessageBox.warning(self, self.t("失敗"), self.t("DLL 無法添加代理配置"))

    def test_all_proxies(self):
        self.append_log("開始測試所有自訂代理 (目標: api.ipify.org)...")
        import threading
        import traceback
        def worker_func():
            try:
                for p in self.custom_proxies:
                    try:
                        success, ms, result = check_proxy_connection(p)
                        if success:
                            p['latency'] = f"{ms}ms (IP: {result})"
                            p['status_color'] = "green" if ms < 500 else "orange"
                            self.redir_signals.log_received.emit(f"測試成功: {p['name']} -> {result}")
                        else:
                            err_msg = str(result)
                            if "timed out" in err_msg: err_msg = "超時"
                            elif "refused" in err_msg: err_msg = "連線被拒"
                            p['latency'] = f"失敗: {err_msg}"
                            p['status_color'] = "red"
                    except Exception as e_inner:
                        p['latency'] = f"錯誤: {str(e_inner)}"
                        p['status_color'] = "red"
                    self.update_proxy_table_signal.emit()
                    time.sleep(0.05) 
                self.redir_signals.log_received.emit(f"所有代理測試完成。")
            except Exception as e:
                err_trace = traceback.format_exc()
                self.redir_signals.log_received.emit(f"測試線程嚴重崩潰:\n{err_trace}")
        t = threading.Thread(target=worker_func, daemon=True)
        t.start()

    def del_custom_proxy(self):
        row = self.table_custom_proxies.currentRow()
        if row < 0: return
        pid = int(self.table_custom_proxies.item(row, 0).text())
        if hasattr(self.bridge.lib, 'NetRedirector_DeleteProxyConfig'):
            self.bridge.lib.NetRedirector_DeleteProxyConfig(pid)
        self.custom_proxies = [p for p in self.custom_proxies if p['id'] != pid]
        self.refresh_custom_proxy_table()
        self.refresh_proxy_combobox()
        # [修正] 代理被刪除後，引用它的規則若不重刷會殘留失效的 proxy ID
        self.reapply_all_rules(only_proxy_id=pid)

    def on_proxy_double_click(self, row, col):
        if row < 0: return
        pid = int(self.table_custom_proxies.item(row, 0).text())
        proxy_data = next((p for p in self.custom_proxies if p['id'] == pid), None)
        if not proxy_data: return
        self.editing_proxy_id = pid
        self.ent_cp_name.setText(proxy_data['name'])
        idx = self.combo_cp_type.findText(proxy_data['type'])
        if idx >= 0: self.combo_cp_type.setCurrentIndex(idx)
        self.ent_cp_ip.setText(proxy_data['ip'])
        self.ent_cp_port.setText(str(proxy_data['port']))
        self.ent_cp_user.setText(proxy_data.get('user', ''))
        self.ent_cp_pass.setText(proxy_data.get('pass', ''))
        self.update_form_titles()

    def cancel_proxy_edit(self):
        self.editing_proxy_id = None
        self.ent_cp_name.clear()
        self.ent_cp_ip.clear()
        self.ent_cp_port.clear()
        self.ent_cp_user.clear()
        self.ent_cp_pass.clear()
        self.update_form_titles()

    def refresh_custom_proxy_table(self):
        scroll = self.table_custom_proxies.verticalScrollBar().value()
        self.table_custom_proxies.setRowCount(0)
        for p in self.custom_proxies:
            row = self.table_custom_proxies.rowCount()
            self.table_custom_proxies.insertRow(row)
            self.table_custom_proxies.setItem(row, 0, QTableWidgetItem(str(p['id'])))
            self.table_custom_proxies.setItem(row, 1, QTableWidgetItem(p['name']))
            self.table_custom_proxies.setItem(row, 2, QTableWidgetItem(p['type']))
            self.table_custom_proxies.setItem(row, 3, QTableWidgetItem(f"{p['ip']}:{p['port']}"))
            auth = "Yes" if p['user'] else "No"
            self.table_custom_proxies.setItem(row, 4, QTableWidgetItem(auth))
            lat_str = str(p.get('latency', '-'))
            lat_item = QTableWidgetItem(lat_str)
            color_code = p.get('status_color', '')
            if color_code == "green":
                lat_item.setForeground(QBrush(QColor("#4CAF50")))
                lat_item.setToolTip(f"測試成功，出口 IP: {lat_str.split('IP:')[-1].strip(')')}")
            elif color_code == "orange":
                lat_item.setForeground(QBrush(QColor("#FF9800")))
            elif color_code == "red":
                lat_item.setForeground(QBrush(QColor("#F44336")))
                lat_item.setToolTip(lat_str)
            else:
                lat_item.setForeground(QBrush(QColor("gray")))
            self.table_custom_proxies.setItem(row, 5, lat_item)
        self.table_custom_proxies.verticalScrollBar().setValue(scroll)

