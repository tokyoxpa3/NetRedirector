# -*- coding: utf-8 -*-
"""IPv6 防洩漏對話框測試 — 網卡勾選、啟用/還原流程、狀態回呼。

以 Qt offscreen 平台執行；PowerShell 一律以注入的 provider/setter 取代，
不顯示視窗、不更動系統設定。
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox

import ipv6_guard_ui
from ipv6_guard_ui import IPv6GuardDialog


class _FakeTimer:
    """攔截 QTimer.singleShot(0, self._refresh)，避免測試開背景執行緒。"""

    @staticmethod
    def singleShot(ms, fn):
        return None


class _FakeMessageBox:
    StandardButton = QMessageBox.StandardButton
    Yes = QMessageBox.StandardButton.Yes
    No = QMessageBox.StandardButton.No
    calls = []
    answer = QMessageBox.StandardButton.Yes

    @classmethod
    def question(cls, *args, **kwargs):
        cls.calls.append(("question", args))
        return cls.answer

    @classmethod
    def information(cls, *args, **kwargs):
        cls.calls.append(("information", args))

    @classmethod
    def warning(cls, *args, **kwargs):
        cls.calls.append(("warning", args))


_ADAPTERS = [
    {
        "name": "乙太網路", "description": "Intel I211", "status": "Up",
        "if_index": 4, "ipv6_enabled": True, "global_ipv6": "2001:b011::1",
    },
    {
        "name": "Wi-Fi", "description": "Intel AX200", "status": "Down",
        "if_index": 7, "ipv6_enabled": False, "global_ipv6": "",
    },
]


def _app():
    return QApplication.instance() or QApplication([])


def _make_dialog(monkeypatch, state=None, adapters=None):
    _app()
    monkeypatch.setattr(ipv6_guard_ui, "QTimer", _FakeTimer)
    monkeypatch.setattr(ipv6_guard_ui, "QMessageBox", _FakeMessageBox)
    _FakeMessageBox.calls = []
    _FakeMessageBox.answer = QMessageBox.StandardButton.Yes
    logs, states = [], []
    dlg = IPv6GuardDialog(
        None,
        state=state,
        on_state_changed=lambda s: states.append(dict(s)),
        log=lambda m: logs.append(m),
        adapter_provider=lambda: {"ok": True,
                                  "adapters": list(adapters or _ADAPTERS),
                                  "error": None},
    )
    # 不開背景執行緒：資料直接餵進 slot
    dlg._on_adapters({"ok": True,
                      "adapters": list(adapters or _ADAPTERS), "error": None})
    return dlg, logs, states


def _row(dlg, name):
    for row in range(dlg.table.rowCount()):
        if dlg.table.item(row, 1).text() == name:
            return row
    raise AssertionError("找不到網卡 {}".format(name))


def _checked(dlg, name):
    return dlg.table.item(_row(dlg, name), 0).checkState() == Qt.CheckState.Checked


def test_dialog_lists_only_physical_and_defaults_to_leaking(monkeypatch):
    dlg, logs, states = _make_dialog(monkeypatch)
    # 注入資料只有實體網卡；清單不會出現任何 VPN 虛擬裝置
    assert dlg.table.rowCount() == 2
    names = [dlg.table.item(r, 1).text() for r in range(2)]
    assert names == ["乙太網路", "Wi-Fi"]
    assert not any("VPN" in n for n in names)
    # 首次使用：只預設勾選「目前 IPv6 啟用、會洩漏」的網卡
    assert _checked(dlg, "乙太網路") is True
    assert _checked(dlg, "Wi-Fi") is False
    assert "啟用 (會洩漏)" in dlg.table.item(_row(dlg, "乙太網路"), 4).text()
    assert dlg.table.item(_row(dlg, "乙太網路"), 5).text() == "2001:b011::1"


def test_dialog_restores_saved_selection(monkeypatch):
    state = {"enabled": True, "adapters": ["Wi-Fi"],
             "original": {"Wi-Fi": True}, "restore_on_exit": False}
    dlg, _, _ = _make_dialog(monkeypatch, state=state)
    assert _checked(dlg, "Wi-Fi") is True
    assert _checked(dlg, "乙太網路") is False
    assert "防護中" in dlg.lbl_status.text()


def test_cell_click_and_toggle_all(monkeypatch):
    dlg, _, _ = _make_dialog(monkeypatch)
    row = _row(dlg, "乙太網路")
    dlg._on_cell_clicked(row, 2)  # 點描述欄 → 翻轉
    assert _checked(dlg, "乙太網路") is False
    dlg._on_cell_clicked(row, 0)  # 勾選欄交給 Qt，不重複翻轉
    assert _checked(dlg, "乙太網路") is False
    dlg._toggle_all()             # 目前全未勾 → 全選
    assert dlg._checked_names() == ["乙太網路", "Wi-Fi"]
    dlg._toggle_all()             # 有勾選 → 全清
    assert dlg._checked_names() == []


def _patch_operation(monkeypatch, dlg, reply_ok=True):
    """把 _start_operation 改成同步餵回結果，驗證完整狀態流轉。"""
    captured = {}

    def fake_start(self, kind, names, original=None):
        captured.update(kind=kind, names=names, original=original)
        if reply_ok:
            results = [{"name": n, "state": "ok", "before": True,
                        "after": kind == "restore", "message": ""}
                       for n in names]
            result = {"ok": True, "results": results,
                      "changed": names, "error": None}
        else:
            result = {"ok": False, "results": [], "changed": [],
                      "error": "Access is denied"}
        dlg._on_operation({"kind": kind, "names": names,
                           "original": original, "result": result})

    monkeypatch.setattr(IPv6GuardDialog, "_start_operation", fake_start)
    monkeypatch.setattr(IPv6GuardDialog, "_refresh", lambda self: None)
    return captured


def test_enable_captures_original_and_notifies(monkeypatch):
    dlg, logs, states = _make_dialog(monkeypatch)
    captured = _patch_operation(monkeypatch, dlg)
    dlg._on_enable()
    assert _FakeMessageBox.calls[0][0] == "question"
    assert captured["kind"] == "disable"
    assert captured["names"] == ["乙太網路"]
    # 原始狀態必須記錄為 True，否則之後還原不了
    assert captured["original"] == {"乙太網路": True}
    assert dlg.state["enabled"] is True
    assert dlg.state["original"] == {"乙太網路": True}
    assert states and states[-1]["enabled"] is True
    assert any("防護生效" in m for m in logs)


def test_enable_while_already_protected_keeps_first_snapshot(monkeypatch):
    state = {"enabled": True, "adapters": ["Wi-Fi"],
             "original": {"Wi-Fi": True}, "restore_on_exit": False}
    # Wi-Fi 目前已被停用，重新啟用時不能被記成 False
    dlg, _, _ = _make_dialog(monkeypatch, state=state)
    dlg.table.item(_row(dlg, "Wi-Fi"), 0).setCheckState(Qt.CheckState.Checked)
    captured = _patch_operation(monkeypatch, dlg)
    dlg._on_enable()
    assert captured["original"]["Wi-Fi"] is True


def test_restore_only_enables_originally_enabled(monkeypatch):
    state = {
        "enabled": True, "adapters": ["乙太網路", "Wi-Fi"],
        "original": {"乙太網路": True, "Wi-Fi": False},
        "restore_on_exit": False,
    }
    dlg, logs, states = _make_dialog(monkeypatch, state=state)
    captured = _patch_operation(monkeypatch, dlg)
    dlg._on_restore()
    # Wi-Fi 是使用者自己關的，還原時不能把它打開
    assert captured["kind"] == "restore"
    assert captured["names"] == ["乙太網路"]
    assert dlg.state["enabled"] is False
    assert dlg.state["original"] == {}
    assert states[-1]["enabled"] is False


def test_failed_operation_does_not_change_state(monkeypatch):
    dlg, logs, states = _make_dialog(monkeypatch)
    _patch_operation(monkeypatch, dlg, reply_ok=False)
    dlg._on_enable()
    assert dlg.state["enabled"] is False
    assert states == []
    assert any("失敗" in m for m in logs)


def test_enable_without_selection_warns(monkeypatch):
    dlg, _, _ = _make_dialog(monkeypatch)
    captured = _patch_operation(monkeypatch, dlg)
    for row in range(dlg.table.rowCount()):
        dlg.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    dlg._on_enable()
    assert "kind" not in captured
    assert _FakeMessageBox.calls[0][0] == "information"


def test_restore_on_exit_checkbox_notifies(monkeypatch):
    dlg, _, states = _make_dialog(monkeypatch)
    dlg.chk_restore_on_exit.setChecked(True)
    assert dlg.state["restore_on_exit"] is True
    assert states[-1]["restore_on_exit"] is True


def test_adapter_list_failure_shows_warning(monkeypatch):
    dlg, logs, _ = _make_dialog(monkeypatch)
    dlg._on_adapters({"ok": False, "error": "Access is denied", "adapters": []})
    assert _FakeMessageBox.calls[-1][0] == "warning"
    assert any("讀取網卡失敗" in m for m in logs)
