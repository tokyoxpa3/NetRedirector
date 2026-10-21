# -*- coding: utf-8 -*-
"""auto_direct 整合測試 — MainWindow 的直連確保與啟動掃描邏輯。

以 stub 取代 MainWindow 的 UI 相依 (bridge / 表格 / 存檔)，把 MainWindow 上
的純邏輯方法綁到 stub 後直接呼叫，驗證核心行為：去重、尊重使用者既有
(含停用) 規則、只處理執行中的進程。
"""
import os
import sys
import types

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import IntegratedApp  # noqa: E402
import process_utils  # noqa: E402

# 這些方法只依賴 stub 提供的屬性，直接借用 MainWindow 的實作
_BOUND_METHODS = (
    "_has_enabled_direct_rule", "_add_auto_direct_rule",
    "_remember_auto_direct",
    "_api_ensure_direct", "_scan_auto_direct_targets",
    "on_auto_direct_toggled",
)


class _FakeBridge:
    def __init__(self, accept=True):
        self.accept = accept
        self.next_id = 1
        self.calls = []

    def add_rule_ex(self, rtype, target, hosts, ports, proto,
                    action, proxy_id):
        self.calls.append((rtype, target, action))
        if not self.accept:
            return 0
        rid = self.next_id
        self.next_id += 1
        return rid


def _make_window():
    w = types.SimpleNamespace()
    w.rules = []
    w.auto_direct = ["MultiSocksDownloader.exe"]
    w.auto_direct_enabled = True
    w.bridge = _FakeBridge()
    w.logs = []
    w.saved = 0
    w.refreshed = 0
    w.t = lambda s: s
    w.append_log = lambda m: w.logs.append(m)
    w.refresh_rules_table = lambda: setattr(w, "refreshed", w.refreshed + 1)
    w._request_save = lambda delay_ms=None: setattr(w, "saved", w.saved + 1)
    w._rule_action_idx = lambda r: int(r.get("action_key", 0))
    for name in _BOUND_METHODS:
        setattr(w, name, types.MethodType(
            getattr(IntegratedApp.MainWindow, name), w))
    return w


def test_ensure_direct_adds_rule_and_remembers():
    w = _make_window()
    result = w._api_ensure_direct("MultiSocksDownloader.exe")
    assert result == {"added": True, "existed": False, "rule_id": 1}
    assert len(w.rules) == 1
    assert w.rules[0]["action_key"] == 1
    assert w.rules[0]["auto"] is True
    assert w.auto_direct == ["MultiSocksDownloader.exe"]  # 已存在，不重複
    assert w.saved >= 1


def test_ensure_direct_is_idempotent():
    w = _make_window()
    w._api_ensure_direct("MultiSocksDownloader.exe")
    result = w._api_ensure_direct("MultiSocksDownloader.exe")
    assert result["added"] is False
    assert result["existed"] is True
    assert len(w.rules) == 1  # 不得堆出重複規則


def test_ensure_direct_registers_new_target():
    w = _make_window()
    w.auto_direct = []
    w._api_ensure_direct("OtherTool.exe")
    assert w.auto_direct == ["OtherTool.exe"]


def test_ensure_direct_rejected_by_driver():
    w = _make_window()
    w.bridge = _FakeBridge(accept=False)
    result = w._api_ensure_direct("X.exe")
    assert result["added"] is False
    assert "error" in result
    assert w.rules == []


def test_scan_adds_only_for_running_and_ruleless(monkeypatch):
    w = _make_window()
    w.auto_direct = ["MultiSocksDownloader.exe", "NotRunning.exe"]
    monkeypatch.setattr(process_utils, "list_process_names",
                        lambda: ["MultiSocksDownloader.exe", "chrome.exe"])
    w._scan_auto_direct_targets()
    assert [r["target"] for r in w.rules] == ["MultiSocksDownloader.exe"]


def test_scan_respects_existing_disabled_rule(monkeypatch):
    """使用者把自動規則停用後，啟動掃描不得又加一條回來。"""
    w = _make_window()
    w.rules = [{"id": 0, "enabled": False, "type": "Name",
                "target": "MultiSocksDownloader.exe", "action_key": 1}]
    monkeypatch.setattr(process_utils, "list_process_names",
                        lambda: ["MultiSocksDownloader.exe"])
    w._scan_auto_direct_targets()
    assert len(w.rules) == 1


def test_scan_noop_when_target_not_running(monkeypatch):
    w = _make_window()
    monkeypatch.setattr(
        process_utils, "list_process_names", lambda: ["chrome.exe"])
    w._scan_auto_direct_targets()
    assert w.rules == []


def test_scan_disabled_when_toggle_off(monkeypatch):
    """齒輪開關關閉時，啟動掃描不動作。"""
    w = _make_window()
    w.auto_direct_enabled = False
    monkeypatch.setattr(process_utils, "list_process_names",
                        lambda: ["MultiSocksDownloader.exe"])
    w._scan_auto_direct_targets()
    assert w.rules == []


def test_toggle_on_restores_defaults_and_scans(monkeypatch):
    """刪除自動規則後，重新開啟齒輪開關會恢復預設清單並重新掃描。"""
    w = _make_window()
    w.auto_direct = []            # 使用者刪除後清空
    w.auto_direct_enabled = False
    monkeypatch.setattr(process_utils, "list_process_names",
                        lambda: ["MultiSocksDownloader.exe"])
    w.on_auto_direct_toggled(True)
    assert w.auto_direct_enabled is True
    assert "MultiSocksDownloader.exe" in w.auto_direct
    assert [r["target"] for r in w.rules] == ["MultiSocksDownloader.exe"]


def test_ensure_direct_allows_generic_interpreter():
    """通用直譯器名稱 (python.exe) 仍可設直連 (呼叫端可能刻意如此)，只記提示。"""
    w = _make_window()
    w.auto_direct = []
    result = w._api_ensure_direct("python.exe")
    assert result["added"] is True
    assert len(w.rules) == 1
    assert w.auto_direct == ["python.exe"]
    assert any("通用直譯器" in m for m in w.logs)


def test_scan_allows_generic_interpreter(monkeypatch):
    w = _make_window()
    w.auto_direct = ["python.exe"]
    monkeypatch.setattr(
        process_utils, "list_process_names", lambda: ["python.exe"])
    w._scan_auto_direct_targets()
    assert [r["target"] for r in w.rules] == ["python.exe"]
