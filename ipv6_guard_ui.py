# -*- coding: utf-8 -*-
"""「IPv6 防洩漏」設定對話框。

由右上角「⚙」選單開啟。只列出實體網卡 (VPN 虛擬裝置不會出現)，讓使用者
自己勾選要停用 TCP/IPv6 的網卡，並提供明確的「還原設定」把原始綁定狀態
還回去。所有 PowerShell 呼叫都放在背景執行緒，完成後以 Qt Signal 回 UI，
避免全機網卡列舉 (約 1~2 秒) 卡住介面。
"""

import threading

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QCheckBox, QMessageBox, QHeaderView, QAbstractItemView,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QColor, QBrush

from i18n import i18n as tr
import ipv6_guard
import ui_theme


class IPv6GuardDialog(QDialog):
    """實體網卡 IPv6 綁定的啟用/還原介面。

    Args:
        parent: 主視窗 (QWidget)
        state: config.json 的 ``ipv6_guard`` 內容 (會先正规化)
        on_state_changed: callable(new_state: dict)，狀態改變時通知主視窗存檔
        log: callable(msg)，寫入主視窗系統日誌
    """

    adapters_ready = Signal(object)
    operation_ready = Signal(object)

    def __init__(self, parent, state=None, on_state_changed=None, log=None,
                 adapter_provider=None, binding_setter=None):
        super().__init__(parent)
        self.state = ipv6_guard.normalize_state(state)
        self._on_state_changed = on_state_changed
        self._log = log
        # 可注入的資料來源，方便單元測試不需真的呼叫 PowerShell
        self._adapter_provider = adapter_provider or ipv6_guard.list_adapters
        self._binding_setter = binding_setter or ipv6_guard.set_binding
        self._adapters = []
        self._busy = False

        self.setWindowTitle(tr.t("IPv6 防洩漏設定"))
        self.setMinimumSize(720, 430)
        self.resize(780, 470)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        intro = QLabel(tr.t(
            "VPN Gate / SoftEther 節點只提供 IPv4，本機 IPv6 會從實體網卡直接連出去，"
            "洩漏真實所在地。停用勾選網卡的 TCP/IPv6 後，瀏覽器會自動改用 IPv4 走 VPN。\n"
            "此設定會影響整台電腦且重開機仍有效，請用「還原設定」復原。"
            "VPN 虛擬網卡不會列出，也不需要停用。"))
        intro.setWordWrap(True)
        intro.setStyleSheet("color: {};".format(ui_theme.COLOR_TEXT_DIM))
        root.addWidget(intro)

        self.lbl_status = QLabel("")
        self.lbl_status.setMinimumHeight(26)
        root.addWidget(self.lbl_status)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            tr.t("勾選"), tr.t("網卡名稱"), tr.t("描述"),
            tr.t("連線狀態"), tr.t("IPv6 綁定"), tr.t("全球 IPv6 位址"),
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        for col, mode in (
            (0, QHeaderView.ResizeMode.ResizeToContents),
            (1, QHeaderView.ResizeMode.ResizeToContents),
            (2, QHeaderView.ResizeMode.Stretch),
            (3, QHeaderView.ResizeMode.ResizeToContents),
            (4, QHeaderView.ResizeMode.ResizeToContents),
            (5, QHeaderView.ResizeMode.ResizeToContents),
        ):
            hh.setSectionResizeMode(col, mode)
        self.table.cellClicked.connect(self._on_cell_clicked)
        self.table.setToolTip(tr.t("點網卡名稱或描述欄即可切換勾選"))
        root.addWidget(self.table, 1)

        self.chk_restore_on_exit = QCheckBox(tr.t("結束程式時自動還原 IPv6"))
        self.chk_restore_on_exit.setChecked(self.state["restore_on_exit"])
        self.chk_restore_on_exit.toggled.connect(self._on_restore_on_exit_changed)
        root.addWidget(self.chk_restore_on_exit)

        tools = QHBoxLayout()
        self.btn_refresh = QPushButton(tr.t("重新整理"))
        self.btn_refresh.clicked.connect(self._refresh)
        self.btn_toggle_all = QPushButton(tr.t("全選 / 取消全選"))
        self.btn_toggle_all.clicked.connect(self._toggle_all)
        tools.addWidget(self.btn_refresh)
        tools.addWidget(self.btn_toggle_all)
        tools.addStretch()
        root.addLayout(tools)

        actions = QHBoxLayout()
        self.btn_enable = QPushButton(tr.t("啟用防護 (停用勾選網卡的 IPv6)"))
        self.btn_enable.setObjectName("DangerBtn")
        self.btn_enable.clicked.connect(self._on_enable)
        self.btn_restore = QPushButton(tr.t("還原設定"))
        self.btn_restore.setObjectName("SuccessBtn")
        self.btn_restore.clicked.connect(self._on_restore)
        self.btn_close = QPushButton(tr.t("關閉"))
        self.btn_close.clicked.connect(self.accept)
        actions.addWidget(self.btn_enable)
        actions.addWidget(self.btn_restore)
        actions.addStretch()
        actions.addWidget(self.btn_close)
        root.addLayout(actions)

        self.adapters_ready.connect(self._on_adapters)
        self.operation_ready.connect(self._on_operation)
        self._update_status()
        QTimer.singleShot(0, self._refresh)

    # ------------------------------------------------------------ 狀態顯示
    def _say(self, msg):
        if self._log:
            try:
                self._log("[IPv6] " + msg)
            except Exception:
                pass

    def _emit_state(self):
        if self._on_state_changed:
            try:
                self._on_state_changed(dict(self.state))
            except Exception:
                pass

    def _update_status(self, busy=False):
        if busy:
            ui_theme.style_badge(self.lbl_status, ui_theme.COLOR_ACCENT)
            self.lbl_status.setText("● " + tr.t("正在讀取/變更網卡設定..."))
            return
        if self.state["enabled"]:
            ui_theme.style_badge(self.lbl_status, ui_theme.COLOR_SUCCESS)
            self.lbl_status.setText("● " + tr.t("防護中：{n} 張實體網卡的 IPv6 已停用").format(
                n=len(self.state["adapters"])))
        else:
            ui_theme.style_badge(self.lbl_status, ui_theme.COLOR_WARN)
            self.lbl_status.setText("● " + tr.t(
                "未啟用：IPv6 流量仍可能從實體網卡洩漏"))

    def _set_busy(self, busy):
        self._busy = busy
        for btn in (self.btn_refresh, self.btn_toggle_all, self.btn_enable,
                    self.btn_restore, self.btn_close):
            btn.setEnabled(not busy)
        self._update_status(busy=busy)

    # ------------------------------------------------------------ 網卡列舉
    def _refresh(self):
        if self._busy:
            return
        self._set_busy(True)

        def work():
            try:
                result = self._adapter_provider()
            except Exception as e:  # noqa: BLE001 — 背景執行緒不得讓例外逸出
                result = {"ok": False, "error": str(e), "adapters": []}
            self.adapters_ready.emit(result)

        threading.Thread(target=work, daemon=True).start()

    def _on_adapters(self, result):
        result = result or {}
        self._set_busy(False)
        if not result.get("ok"):
            self._say(tr.t("讀取網卡失敗: {err}").format(err=result.get("error")))
            QMessageBox.warning(
                self, tr.t("IPv6 防洩漏設定"),
                tr.t("無法讀取實體網卡：{err}\n\n請確認以系統管理員身分執行。").format(
                    err=result.get("error")))
            return

        self._adapters = list(result.get("adapters") or [])
        self._fill_table()
        if not self._adapters:
            self._say(tr.t("找不到可設定的實體網卡"))

    def _fill_table(self):
        saved = set(self.state["adapters"])
        self.table.setRowCount(0)
        for ad in self._adapters:
            row = self.table.rowCount()
            self.table.insertRow(row)
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            if saved:
                checked = ad["name"] in saved
            else:
                # 首次使用：預設勾選「目前有 IPv6、會洩漏」的網卡
                checked = bool(ad["ipv6_enabled"])
            chk.setCheckState(
                Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, chk)
            self.table.setItem(row, 1, QTableWidgetItem(ad["name"]))
            self.table.setItem(row, 2, QTableWidgetItem(ad["description"]))
            self.table.setItem(row, 3, QTableWidgetItem(ad["status"]))

            if ad["ipv6_enabled"]:
                bind_item = QTableWidgetItem(tr.t("啟用 (會洩漏)"))
                bind_item.setForeground(QBrush(QColor(ui_theme.COLOR_DANGER)))
            else:
                bind_item = QTableWidgetItem(tr.t("已停用 (已防護)"))
                bind_item.setForeground(QBrush(QColor(ui_theme.COLOR_SUCCESS)))
            self.table.setItem(row, 4, bind_item)

            g6_item = QTableWidgetItem(ad["global_ipv6"] or "—")
            if ad["global_ipv6"]:
                g6_item.setForeground(QBrush(QColor(ui_theme.COLOR_DANGER)))
            self.table.setItem(row, 5, g6_item)

    def _on_cell_clicked(self, row, col):
        # 勾選欄由 Qt 自行處理指示器；點其他欄則手動切換，避免「點整列沒反應」
        if col == 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        new_state = (Qt.CheckState.Unchecked
                     if item.checkState() == Qt.CheckState.Checked
                     else Qt.CheckState.Checked)
        item.setCheckState(new_state)

    def _toggle_all(self):
        checked_names = self._checked_names()
        target = (Qt.CheckState.Unchecked if checked_names
                  else Qt.CheckState.Checked)
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                item.setCheckState(target)

    def _checked_names(self):
        names = []
        for row in range(self.table.rowCount()):
            chk = self.table.item(row, 0)
            name_item = self.table.item(row, 1)
            if chk and name_item and chk.checkState() == Qt.CheckState.Checked:
                names.append(name_item.text())
        return names

    # ------------------------------------------------------------ 啟用/還原
    def _start_operation(self, kind, names, original=None):
        self._set_busy(True)

        def work():
            try:
                result = self._binding_setter(names, kind == "restore")
            except Exception as e:  # noqa: BLE001
                result = {"ok": False, "error": str(e),
                          "results": [], "changed": []}
            self.operation_ready.emit({
                "kind": kind, "names": names,
                "original": original, "result": result,
            })

        threading.Thread(target=work, daemon=True).start()

    def _on_enable(self):
        names = self._checked_names()
        if not names:
            QMessageBox.information(
                self, tr.t("IPv6 防洩漏設定"),
                tr.t("請先勾選至少一張實體網卡。"))
            return
        reply = QMessageBox.question(
            self, tr.t("啟用 IPv6 防洩漏"),
            tr.t("即將停用下列實體網卡的 TCP/IPv6：\n\n{names}\n\n"
                 "整台電腦的 IPv6 連線會中斷 (含本機區網 IPv6、IPv6 DNS)，"
                 "直到按「還原設定」為止。VPN 虛擬網卡不受影響。\n\n確定繼續？").format(
                names="、".join(names)),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        original = ipv6_guard.merge_original(
            self.state["original"], self._adapters, names, self.state["enabled"])
        self._start_operation("disable", names, original=original)

    def _on_restore(self):
        names = ipv6_guard.plan_restore(self.state)
        missing_original = not self.state["original"]
        if not names:
            names = self._checked_names()
            missing_original = True
        if not names:
            QMessageBox.information(
                self, tr.t("IPv6 防洩漏設定"),
                tr.t("目前沒有需要還原的網卡。"))
            return
        warn = ""
        if missing_original:
            warn = tr.t(
                "\n\n注意：找不到原始綁定紀錄，將直接啟用這些網卡的 IPv6。"
                "若其中有你原本就手動關閉的網卡，請自行再關閉一次。")
        reply = QMessageBox.question(
            self, tr.t("還原 IPv6 設定"),
            tr.t("即將重新啟用下列網卡的 TCP/IPv6：\n\n{names}{warn}\n\n確定繼續？").format(
                names="、".join(names), warn=warn),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._start_operation("restore", names)

    def _on_operation(self, payload):
        payload = payload or {}
        kind = payload.get("kind")
        names = payload.get("names") or []
        result = payload.get("result") or {}
        self._set_busy(False)

        if not result.get("ok"):
            self._say(tr.t("變更 IPv6 綁定失敗: {err}").format(
                err=result.get("error")))
            QMessageBox.warning(
                self, tr.t("IPv6 防洩漏設定"),
                tr.t("變更失敗：{err}\n\n請確認以系統管理員身分執行。").format(
                    err=result.get("error")))
            self._refresh()
            return

        failures = [r for r in result.get("results", [])
                    if r.get("state") != "ok"]
        for r in failures:
            self._say(tr.t("{name}: {msg}").format(
                name=r.get("name"), msg=r.get("message") or r.get("state")))
        applied = [r for r in result.get("results", [])
                   if r.get("state") == "ok"]

        if kind == "disable":
            if applied:
                self.state["enabled"] = True
                self.state["original"] = dict(payload.get("original") or {})
                # 以原始狀態紀錄為準：防護中若重新勾選，舊網卡不能從清單消失，
                # 否則這些仍被停用的網卡會漏掉還原/啟動重新套用。
                self.state["adapters"] = (
                    list(self.state["original"].keys()) or list(names))
                self._say(tr.t("已停用 {n} 張實體網卡的 IPv6，防護生效").format(
                    n=len(applied)))
            else:
                self._say(tr.t("沒有任何網卡被變更"))
        else:
            self.state["enabled"] = False
            self.state["original"] = {}
            self._say(tr.t("已還原 {n} 張網卡的 IPv6 綁定").format(
                n=len(applied)))

        self._emit_state()
        self._update_status()
        self._refresh()

    def _on_restore_on_exit_changed(self, checked):
        self.state["restore_on_exit"] = bool(checked)
        self._emit_state()
