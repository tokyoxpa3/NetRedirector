# -*- coding: utf-8 -*-
"""規則分頁 mixin (自 IntegratedApp.MainWindow 抽出)

版面自 demo_modern_ui.py 的規則分頁移植：工具列 + 全寬規則表格，
表單改為彈出式對話框 (不再常駐佔用分頁垂直空間)，並提供
「從執行中進程選擇」的進程挑選器。
"""

import logging

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QTableWidget, QTableWidgetItem, QPushButton, QLabel,
                             QMessageBox, QHeaderView, QComboBox, QLineEdit,
                             QRadioButton, QButtonGroup, QMenu, QDialog,
                             QFormLayout, QCheckBox, QAbstractItemView)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QBrush, QAction

from i18n import i18n as tr
from autosave import AutoSaveMixin
import proxy_core  # noqa: F401 — 模組化測試要求 mixin 模組可解析此名稱
import rule_utils
import ui_theme
import process_utils


def _rule_action_index(rule_data):
    """規則資料 → 動作索引 (0=PROXY, 1=DIRECT, 2=BLOCK)。"""
    key = rule_data.get('action_key')
    if key is not None:
        try:
            return int(key)
        except (TypeError, ValueError):
            pass
    action = rule_data.get('action', '')
    if "DIRECT" in action: return 1
    if "BLOCK" in action: return 2
    return 0


class ProcessPickerDialog(QDialog):
    """從執行中進程清單挑選目標 (供規則對話框與工具列使用)。

    底部兩顆確認按鈕即代表目標類型 (進程名稱 / PID)，取代先前的類型
    選項 + 單一確定按鈕；default_mode 僅決定雙擊列與主要按鈕樣式。
    """

    def __init__(self, parent=None, default_mode="Name"):
        super().__init__(parent)
        self.setWindowTitle(tr.t("從執行中進程選擇"))
        self.resize(520, 560)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        top = QHBoxLayout()
        self.ent_filter = QLineEdit()
        self.ent_filter.setPlaceholderText(tr.t("🔍 篩選進程名稱..."))
        self.ent_filter.textChanged.connect(self.apply_filter)
        top.addWidget(self.ent_filter, 1)
        btn_refresh = QPushButton(tr.t("重新整理"))
        btn_refresh.clicked.connect(self.reload)
        top.addWidget(btn_refresh)
        layout.addLayout(top)

        # 目標類型改由下方兩顆確認按鈕決定；default_mode 只決定雙擊列
        # 與主要按鈕樣式落在進程名稱還是 PID。
        self._default_mode = "PID" if default_mode == "PID" else "Name"
        self._chosen_mode = self._default_mode

        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels([tr.t("Process Name"), tr.t("PID")])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.cellDoubleClicked.connect(lambda *_: self.on_ok())
        layout.addWidget(self.table, 1)

        btns = QHBoxLayout()
        btns.addStretch()
        btn_cancel = QPushButton(tr.t("取消"))
        btn_cancel.clicked.connect(self.reject)
        btns.addWidget(btn_cancel)

        # 確認即選定目標類型：兩顆按鈕分別以進程名稱 / PID 作為規則目標
        self.btn_use_name = QPushButton(tr.t("使用進程名稱"))
        self.btn_use_name.clicked.connect(lambda: self.on_ok("Name"))
        btns.addWidget(self.btn_use_name)

        self.btn_use_pid = QPushButton(tr.t("使用 PID"))
        self.btn_use_pid.clicked.connect(lambda: self.on_ok("PID"))
        btns.addWidget(self.btn_use_pid)

        default_btn = (self.btn_use_pid if self._default_mode == "PID"
                       else self.btn_use_name)
        default_btn.setObjectName("PrimaryBtn")
        layout.addLayout(btns)

        self.reload()

    def reload(self):
        processes = process_utils.list_processes()
        self.table.setRowCount(0)
        for name, pid in processes:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(str(pid)))
        self.apply_filter()

    def apply_filter(self):
        keyword = self.ent_filter.text().strip().lower()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            name = item.text().lower() if item else ""
            self.table.setRowHidden(row, bool(keyword) and keyword not in name)

    def selected_mode(self):
        """目前選擇以進程名稱或 PID 作為規則目標 ("Name" / "PID")。

        由下方確認按鈕決定；未按下任何按鈕時即 default_mode (雙擊列同此)。
        """
        return self._chosen_mode

    def selected_process(self):
        """回傳 (進程名稱, PID)；未選取時回傳 ("", 0)。"""
        row = self.table.currentRow()
        if row < 0:
            return "", 0
        name_item = self.table.item(row, 0)
        pid_item = self.table.item(row, 1)
        if name_item is None:
            return "", 0
        pid_text = pid_item.text() if pid_item else ""
        return name_item.text(), int(pid_text) if pid_text.isdigit() else 0

    def on_ok(self, mode=None):
        """確認挑選；mode 為所按按鈕指定的目標類型 ("Name" / "PID")。"""
        if mode:
            self._chosen_mode = mode
        if self.table.currentRow() < 0:
            QMessageBox.information(self, tr.t("提示"), tr.t("請先選擇一個進程"))
            return
        self.accept()


class RuleDialog(QDialog):
    """新增 / 編輯攔截規則對話框。

    對齊 demo_modern_ui 的彈窗形式：表單不再常駐於分頁，規則清單可以
    佔滿整個分頁高度。目標欄旁提供「📂」按鈕直接從執行中進程挑選。
    """

    def __init__(self, parent=None, rule_data=None, proxy_choices=None,
                 default_target="", default_is_pid=False):
        super().__init__(parent)
        self._editing = rule_data is not None
        self.setWindowTitle(
            tr.t("編輯規則 (ID: {rule_id})").format(rule_id=rule_data.get('id', 0))
            if self._editing else tr.t("新增攔截規則"))
        self.resize(520, 380)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(12)

        type_row = QHBoxLayout()
        self.rb_name = QRadioButton(tr.t("Process Name"))
        self.rb_pid = QRadioButton(tr.t("PID"))
        self.rb_name.setChecked(True)
        self._type_group = QButtonGroup(self)
        self._type_group.addButton(self.rb_name, 0)
        self._type_group.addButton(self.rb_pid, 1)
        type_row.addWidget(self.rb_name)
        type_row.addWidget(self.rb_pid)
        type_row.addStretch()
        form.addRow(tr.t("類型"), type_row)

        target_row = QHBoxLayout()
        self.ent_target = QLineEdit()
        # 目標留空時由 get_data() 帶入 "*" (核心視為所有進程)。
        self.ent_target.setPlaceholderText(
            tr.t("例如: chrome.*;Game*.exe ，或 PID 1234 (留空 * = 全部進程)"))
        self.btn_browse = QPushButton("📂")
        self.btn_browse.setFixedWidth(42)
        self.btn_browse.setToolTip(tr.t("從執行中進程選擇"))
        self.btn_browse.clicked.connect(self.browse_process)
        target_row.addWidget(self.ent_target, 1)
        target_row.addWidget(self.btn_browse)
        form.addRow(tr.t("目標:"), target_row)

        # 不預填 "*"：預填會讓 placeholder 永遠不顯示，留空則由
        # normalize_rule_pattern 在 get_data() 補回預設值。
        self.ent_hosts = QLineEdit()
        self.ent_hosts.setPlaceholderText(
            tr.t("IP/域名 (預設 *) 例: 8.8.8.8;*.google.com;192.168.*.*"
                 ";2001:db8::/32"))
        form.addRow(tr.t("Hosts:"), self.ent_hosts)

        self.ent_ports = QLineEdit()
        self.ent_ports.setPlaceholderText(tr.t("Port (預設 *) 例: 443;1000-2000"))
        form.addRow(tr.t("Ports:"), self.ent_ports)

        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["BOTH", "TCP", "UDP"])
        form.addRow(tr.t("Proto:"), self.combo_proto)

        self.combo_action = QComboBox()
        self.combo_action.addItems([
            tr.t("PROXY (轉發)"), tr.t("DIRECT (直連)"), tr.t("BLOCK (阻擋)")])
        form.addRow(tr.t("動作:"), self.combo_action)

        self.combo_proxy = QComboBox()
        form.addRow(tr.t("指定代理:"), self.combo_proxy)
        self.reload_proxies(proxy_choices or [])

        layout.addLayout(form)
        layout.addStretch()

        btn_box = QHBoxLayout()
        btn_box.addStretch()
        btn_cancel = QPushButton(tr.t("取消修改"))
        btn_cancel.clicked.connect(self.reject)
        self.btn_save = QPushButton(
            tr.t("保存修改") if self._editing else tr.t("新增規則"))
        ui_theme.set_button_kind(
            self.btn_save, "WarnBtn" if self._editing else "PrimaryBtn")
        self.btn_save.clicked.connect(self.accept)
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(self.btn_save)
        layout.addLayout(btn_box)

        if self._editing:
            self._load(rule_data)
        elif default_target:
            self.ent_target.setText(str(default_target))
            if default_is_pid:
                self.rb_pid.setChecked(True)

    def _load(self, rule_data):
        self.ent_target.setText(rule_data.get('target', ''))
        self.ent_hosts.setText(rule_data.get('hosts', '*'))
        self.ent_ports.setText(rule_data.get('ports', '*'))
        if rule_data.get('type') == 'PID':
            self.rb_pid.setChecked(True)
        else:
            self.rb_name.setChecked(True)
        idx = self.combo_proto.findText(rule_data.get('proto', 'BOTH'))
        if idx >= 0:
            self.combo_proto.setCurrentIndex(idx)
        self.combo_action.setCurrentIndex(_rule_action_index(rule_data))
        idx = self.combo_proxy.findText(rule_data.get('proxy', ''))
        if idx >= 0:
            self.combo_proxy.setCurrentIndex(idx)

    def reload_proxies(self, items):
        """重填代理下拉並盡量保留原選取 (以 proxy_id 優先，文字其次)。"""
        current_data = self.combo_proxy.currentData()
        current_text = self.combo_proxy.currentText()
        self.combo_proxy.blockSignals(True)
        self.combo_proxy.clear()
        for text, proxy_id in items:
            self.combo_proxy.addItem(text, proxy_id)
        idx = self.combo_proxy.findData(current_data)
        if idx < 0 and current_text:
            idx = self.combo_proxy.findText(current_text)
        if idx >= 0:
            self.combo_proxy.setCurrentIndex(idx)
        self.combo_proxy.blockSignals(False)

    def browse_process(self):
        dialog = ProcessPickerDialog(
            self, default_mode="PID" if self.rb_pid.isChecked() else "Name")
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, pid = dialog.selected_process()
        if not name:
            return
        # 挑選器可切換以名稱或 PID 為目標，據此同步對話框的匹配模式
        if dialog.selected_mode() == "PID":
            self.rb_pid.setChecked(True)
            self.ent_target.setText(str(pid))
        else:
            self.rb_name.setChecked(True)
            self.ent_target.setText(name)

    def get_data(self):
        """收集表單內容 (已正規化全形星號等)。"""
        return {
            'type': 'PID' if self.rb_pid.isChecked() else 'Name',
            'target': rule_utils.normalize_rule_target(
                self.ent_target.text(), default="*"),
            'hosts': rule_utils.normalize_rule_pattern(self.ent_hosts.text()),
            'ports': rule_utils.normalize_rule_pattern(self.ent_ports.text()),
            'proto': self.combo_proto.currentText(),
            'action_idx': self.combo_action.currentIndex(),
            'proxy_id': int(self.combo_proxy.currentData() or 0),
        }


class RulesTabMixin(AutoSaveMixin):
    def setup_rules_tab(self):
        layout = QVBoxLayout(self.tab_rules)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # ---------- 工具列 ----------
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.btn_add_rule = QPushButton("")
        self.btn_add_rule.setObjectName("PrimaryBtn")
        self._reg("text", self.btn_add_rule, "➕ 新增攔截規則")
        self.btn_add_rule.clicked.connect(lambda: self.open_add_rule_dialog())
        toolbar.addWidget(self.btn_add_rule)

        self.btn_pick_process = QPushButton("")
        self._reg("text", self.btn_pick_process, "📂 從執行中進程選擇...")
        self.btn_pick_process.clicked.connect(self.pick_process_for_rule)
        toolbar.addWidget(self.btn_pick_process)

        self.btn_del_rule = QPushButton("")
        self._reg("text", self.btn_del_rule, "🗑 刪除選取")
        self.btn_del_rule.clicked.connect(self.del_rule)
        toolbar.addWidget(self.btn_del_rule)

        toolbar.addSpacing(16)

        self.ent_rule_search = QLineEdit()
        self.ent_rule_search.setFixedWidth(240)
        self._reg("placeholder", self.ent_rule_search,
                  "🔍 快速搜尋規則 (目標/主機/代理)...")
        self.ent_rule_search.textChanged.connect(self.apply_rule_filter)
        toolbar.addWidget(self.ent_rule_search)

        toolbar.addStretch()
        lbl_hint = QLabel("")
        self._reg("text", lbl_hint, "💡 提示：雙擊規則列可編輯，或按右鍵開啟選單")
        lbl_hint.setStyleSheet("color: #64748B; font-size: 12px;")
        toolbar.addWidget(lbl_hint)
        layout.addLayout(toolbar)

        # ---------- 規則表格 ----------
        self.table_rules = QTableWidget()
        cols = ["啟用", "類型", "目標", "Hosts", "Ports", "Proto", "動作", "代理", "ID"]
        self.table_rules.setColumnCount(len(cols))
        self._reg("headers", self.table_rules, cols)
        self.table_rules.verticalHeader().setVisible(False)
        # 短欄位依內容自動收合，目標/代理(變動文字)才伸展；ID 只供內部除錯
        for col in (0, 1, 3, 4, 5, 6):
            self.table_rules.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents)
        self.table_rules.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch)
        self.table_rules.horizontalHeader().setSectionResizeMode(
            7, QHeaderView.ResizeMode.Stretch)
        self.table_rules.setColumnHidden(8, True)
        self.table_rules.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table_rules.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_rules.cellDoubleClicked.connect(self.on_rule_double_click)
        self.table_rules.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table_rules.customContextMenuRequested.connect(self.show_rule_menu)
        layout.addWidget(self.table_rules)

    # ----------------------------------------------------------- 代理清單
    def proxy_choices(self):
        """規則可指派的代理清單 [(顯示文字, proxy_id), ...]。"""
        items = []
        for port, pid in sorted(self.hub_proxy_map.items()):
            items.append((f"[Hub] Local Port {port}", pid))
        for p in self.custom_proxies:
            items.append((f"[Custom] {p['name']}", p['id']))
        if not items:
            items.append((self.t("未指定 (Fallback to Direct)"), 0))
        return items

    def _proxy_display(self, proxy_id):
        target = int(proxy_id or 0)
        for text, pid in self.proxy_choices():
            if int(pid or 0) == target:
                return text
        return self.t("未指定 (Fallback to Direct)")

    def _proxy_stable_name(self, proxy_id):
        """從代理 ID 反推穩定識別, 加命名空間前綴:
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

    # ----------------------------------------------------------- 對話框
    def open_add_rule_dialog(self, default_target="", default_is_pid=False):
        dialog = RuleDialog(
            self, proxy_choices=self.proxy_choices(),
            default_target=default_target, default_is_pid=default_is_pid)
        self._rule_dialog = dialog
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.apply_rule_dialog_data(dialog.get_data(), None)
        finally:
            self._rule_dialog = None

    def open_edit_rule_dialog(self, rule_data):
        dialog = RuleDialog(
            self, rule_data=rule_data, proxy_choices=self.proxy_choices())
        self._rule_dialog = dialog
        try:
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.apply_rule_dialog_data(dialog.get_data(), rule_data)
        finally:
            self._rule_dialog = None

    def pick_process_for_rule(self):
        """工具列入口：挑選進程後開啟新增規則對話框，目標可為名稱或 PID。"""
        dialog = ProcessPickerDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        name, pid = dialog.selected_process()
        if not name:
            return
        if dialog.selected_mode() == "PID":
            self.open_add_rule_dialog(default_target=str(pid), default_is_pid=True)
        else:
            self.open_add_rule_dialog(default_target=name)

    def apply_rule_dialog_data(self, data, editing_rule):
        """把對話框內容寫入 DLL 與記憶體清單 (新增或原地更新)。"""
        target = data['target']
        is_pid = data['type'] == 'PID'
        if not target:
            QMessageBox.warning(self, self.t("警告"), self.t("請輸入目標進程"))
            return
        if is_pid and not (target.isascii() and target.isdigit()):
            # [Fixed] isascii 檔掉全形數字 ('１２３') 與上標數字 ('²') —
            # isdigit() 對它們為 True 但 int() 可能抛 ValueError
            QMessageBox.warning(self, self.t("錯誤"), self.t("PID 需為數字"))
            return

        hosts = data['hosts']
        ports = data['ports']
        proto_str = data['proto']
        action_idx = data['action_idx']
        pid_proxy = int(data['proxy_id'] or 0)
        proxy_text = self._proxy_display(pid_proxy)
        proxy_name = self._proxy_stable_name(pid_proxy)

        was_edit = editing_rule is not None
        enabled = True if not was_edit else bool(editing_rule.get('enabled', True))
        rid = 0

        if was_edit:
            old_id = int(editing_rule.get('id') or 0)
            old_is_pid = editing_rule.get('type') == 'PID'
            # [改進] 名稱規則優先「原地更新」(EditRuleWithProxy 保留相同 ID)，
            # 避免規則 ID 跳動；PID 規則或名稱/PID 類型切換才需刪除重建
            # (C 核心的 EditRuleWithProxy 不處理 target_pid 欄位)。
            if enabled and not is_pid and not old_is_pid:
                if self.bridge.edit_rule_ex(
                        old_id, target, hosts, ports, proto_str, action_idx, pid_proxy):
                    rid = old_id  # ID 不變，原地生效
            if enabled and rid == 0 and old_id:
                self.bridge.delete_rule(old_id)

        if enabled and rid == 0:
            rid = self.bridge.add_rule_ex(
                'PID' if is_pid else 'Name', target, hosts, ports,
                proto_str, action_idx, pid_proxy)
            if rid <= 0:
                QMessageBox.warning(
                    self, self.t("失敗"), self.t("驅動返回錯誤，規則添加失敗。"))
                return

        new_rule = {
            'id': int(rid),
            'enabled': enabled,
            'type': 'PID' if is_pid else 'Name',
            'target': target,
            'hosts': hosts,
            'ports': ports,
            'proto': proto_str,
            'action': self.t(
                ["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"][action_idx]),
            'action_key': action_idx,
            'proxy': proxy_text,
            'proxy_name': proxy_name,
            'proxy_id': pid_proxy,   # [Fixed] 最後已知 ID: 供刪除代理時重刷規則
        }
        if was_edit:
            # 以物件身分 (is) 定位，避免兩條內容相同的規則被 dict 值比對誤中
            for index, existing in enumerate(self.rules):
                if existing is editing_rule:
                    self.rules[index] = new_rule
                    break
            else:
                self.rules.append(new_rule)
        else:
            self.rules.append(new_rule)
        self.refresh_rules_table()
        self.append_log(f"規則已{'更新' if was_edit else '新增'} (ID: {rid})")
        self._request_save()

    # ----------------------------------------------------------- 啟用/停用
    def toggle_rule_enabled(self, rule_data, checked):
        if checked:
            self._enable_rule(rule_data)
        else:
            self._disable_rule(rule_data)
        # 重建表格 (延後執行，避免在勾選框自身的信號處理中刪除發送者)
        QTimer.singleShot(0, self.refresh_rules_table)
        self._request_save()

    def _enable_rule(self, rule_data):
        proxy_id, _display = self._resolve_proxy(rule_data)
        if proxy_id == 0 and self._rule_action_idx(rule_data) == 0:
            # 與 reapply_all_rules 一致：引用的代理已不存在時轉為直連，
            # 避免核心對 PROXY+0 直接斷線形成黑洞
            rule_data['action_key'] = 1
            rule_data['action'] = self.t("DIRECT (直連)")
            rule_data['proxy_name'] = ''
            rule_data['proxy'] = self.t("未指定 (Fallback to Direct)")
            self.append_log(f"規則 '{rule_data['target']}' 引用的代理已不存在，已轉為直連")
        rid = self.bridge.add_rule_ex(
            rule_data['type'], rule_data['target'],
            rule_data.get('hosts', '*'), rule_data.get('ports', '*'),
            rule_data.get('proto', 'BOTH'), self._rule_action_idx(rule_data),
            int(proxy_id))
        if rid > 0:
            rule_data['id'] = rid
            rule_data['enabled'] = True
            rule_data['proxy_id'] = int(proxy_id)
            self.append_log(f"規則已啟用 (ID: {rid})")
            return True
        QMessageBox.warning(
            self, self.t("失敗"), self.t("驅動返回錯誤，規則添加失敗。"))
        return False

    def _disable_rule(self, rule_data):
        rid = int(rule_data.get('id') or 0)
        if rid:
            self.bridge.delete_rule(rid)
        rule_data['id'] = 0
        rule_data['enabled'] = False
        self.append_log(f"規則已停用: {rule_data['target']}")

    # ----------------------------------------------------------- 表格
    def _rule_at_row(self, row):
        """表格列索引即 self.rules 索引 (篩選只隱藏列，不移除)。"""
        if 0 <= row < len(self.rules):
            return self.rules[row]
        return None

    def on_rule_double_click(self, row, col):
        rule_data = self._rule_at_row(row)
        if rule_data is not None:
            self.open_edit_rule_dialog(rule_data)

    def _rule_action_idx(self, rule_data):
        return _rule_action_index(rule_data)

    def _action_display(self, rule_data):
        return self.t(
            ["PROXY (轉發)", "DIRECT (直連)", "BLOCK (阻擋)"][self._rule_action_idx(rule_data)])

    def _action_color(self, rule_data):
        idx = self._rule_action_idx(rule_data)
        if idx == 0:
            return ui_theme.COLOR_ACCENT
        if idx == 1:
            return ui_theme.COLOR_SUCCESS
        return ui_theme.COLOR_DANGER

    def del_rule(self):
        row = self.table_rules.currentRow()
        rule_data = self._rule_at_row(row)
        if rule_data is None:
            return
        if rule_data.get('enabled', True) and rule_data.get('id'):
            self.bridge.delete_rule(int(rule_data['id']))
        # 自動加入的規則被刪除時，一併移出 auto_direct 清單；否則下次啟動
        # 掃描會把它又加回來，使用者會覺得刪不掉
        if rule_data.get('auto') and hasattr(self, 'auto_direct'):
            target = str(rule_data.get('target', '')).lower()
            self.auto_direct = [
                t for t in self.auto_direct if t.lower() != target]
            self.append_log(
                f"已停止自動加入 {rule_data.get('target')} 的直連"
                f"（該程式下次啟動時會重新註冊）")
        self.rules = [r for r in self.rules if r is not rule_data]
        self.refresh_rules_table()
        self._request_save()

    def refresh_rules_table(self):
        scroll = self.table_rules.verticalScrollBar().value()
        self.table_rules.setRowCount(0)
        for r in self.rules:
            row = self.table_rules.rowCount()
            self.table_rules.insertRow(row)
            enabled = bool(r.get('enabled', True))

            chk = QCheckBox()
            chk.setChecked(enabled)
            chk.setCursor(Qt.CursorShape.PointingHandCursor)
            chk.toggled.connect(
                lambda checked, rule=r: self.toggle_rule_enabled(rule, checked))
            wrap = QWidget()
            wrap.setObjectName("CellWrap")
            wrap_layout = QHBoxLayout(wrap)
            wrap_layout.setContentsMargins(0, 0, 0, 0)
            wrap_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            wrap_layout.addWidget(chk)
            self.table_rules.setCellWidget(row, 0, wrap)

            self.table_rules.setItem(row, 1, QTableWidgetItem(r['type']))
            # 由本機控制 API 自動加入的規則加上標記，避免使用者誤解來源
            target_text = r['target'] + (self.t(" (自動)") if r.get('auto') else "")
            self.table_rules.setItem(row, 2, QTableWidgetItem(target_text))
            self.table_rules.setItem(row, 3, QTableWidgetItem(r.get('hosts', '*')))
            self.table_rules.setItem(row, 4, QTableWidgetItem(r.get('ports', '*')))
            self.table_rules.setItem(row, 5, QTableWidgetItem(r.get('proto', 'BOTH')))

            action_item = QTableWidgetItem(self._action_display(r))
            action_item.setForeground(QBrush(QColor(self._action_color(r))))
            self.table_rules.setItem(row, 6, action_item)
            self.table_rules.setItem(row, 7, QTableWidgetItem(r.get('proxy', '')))
            self.table_rules.setItem(row, 8, QTableWidgetItem(str(r.get('id', 0))))

            if not enabled:
                for col in range(1, 9):
                    item = self.table_rules.item(row, col)
                    if item is not None:
                        item.setForeground(QBrush(QColor("#64748B")))
        self.apply_rule_filter()
        self.table_rules.verticalScrollBar().setValue(scroll)

    def _rule_row_matches(self, row):
        keyword = self.ent_rule_search.text().strip().lower()
        if not keyword:
            return True
        for col in range(1, 8):
            item = self.table_rules.item(row, col)
            if item and keyword in item.text().lower():
                return True
        return False

    def apply_rule_filter(self):
        for row in range(self.table_rules.rowCount()):
            self.table_rules.setRowHidden(row, not self._rule_row_matches(row))
