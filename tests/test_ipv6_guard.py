# -*- coding: utf-8 -*-
"""ipv6_guard 單元測試 — PowerShell 腳本組成、輸出解析與狀態/還原邏輯。

外部命令一律 mock，測試不會更動任何系統網路設定。
"""
import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ipv6_guard


def _adapter(name="乙太網路", enabled=True, g6="2001:b011::1"):
    return {
        "name": name, "description": "Intel(R) I211 Gigabit Network Connection",
        "status": "Up", "if_index": 4,
        "ipv6_enabled": enabled, "global_ipv6": g6,
    }


# ---------------------------------------------------------------- 腳本組成

def test_list_script_only_physical_and_excludes_virtual():
    script = ipv6_guard._build_list_script()
    assert "Get-NetAdapter -Physical" in script
    assert "ms_tcpip6" in script
    assert "Get-NetAdapterBinding" in script
    assert "NRJSON:" in script
    # VPN 虛擬裝置關鍵字黑名單 (16 張 SoftEther + VMware 不該出現)
    for kw in ("softether", "vpn", "vmware", "hyper-v", "tap"):
        assert "'{}'".format(kw) in script
    # -Physical 誤判為空時的退路
    assert "-not $_.Virtual" in script
    # link-local / ::1 不算「會洩漏」的全球位址
    assert "fe80*" in script


def test_set_script_payload_is_base64_json_and_safe_for_quotes():
    names = ["乙太網路", "O'Brien NIC", 'Wi-Fi "2"']
    script = ipv6_guard._build_set_script(names, False)
    assert "Disable-NetAdapterBinding" in script
    assert "Enable-NetAdapterBinding" in script
    assert "__PAYLOAD_B64__" not in script
    assert "-ComponentID ms_tcpip6" in script

    marker = "FromBase64String('"
    b64 = script.split(marker, 1)[1].split("')", 1)[0]
    payload = json.loads(base64.b64decode(b64).decode("utf-8"))
    assert payload == {"enabled": False, "names": names}
    # 名稱不能裸露在腳本裡 (避免引號注入)
    assert "O'Brien" not in script


def test_run_powershell_uses_encoded_command_utf16(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(ipv6_guard.subprocess, "run", fake_run)
    ipv6_guard._run_powershell("Write-Output '乙太網路'")

    cmd = captured["cmd"]
    assert cmd[0] == "powershell"
    assert "-NoProfile" in cmd and "-NonInteractive" in cmd
    assert "-EncodedCommand" in cmd
    script = base64.b64decode(cmd[cmd.index("-EncodedCommand") + 1])
    assert script.decode("utf-16-le") == "Write-Output '乙太網路'"
    assert captured["kwargs"]["timeout"] == ipv6_guard._TIMEOUT


# ---------------------------------------------------------------- 列舉解析

def _mock_ps(monkeypatch, rc=0, out="", err=""):
    monkeypatch.setattr(ipv6_guard.sys, "platform", "win32")
    monkeypatch.setattr(ipv6_guard, "_run_powershell",
                        lambda script: (rc, out, err))


def test_list_adapters_parses_json_and_normalizes(monkeypatch):
    rows = [_adapter(), _adapter("Wi-Fi", False, "")]
    out = "NRJSON:" + json.dumps(rows, ensure_ascii=False)
    _mock_ps(monkeypatch, out=out)
    result = ipv6_guard.list_adapters()
    assert result["ok"] is True
    assert result["error"] is None
    assert [a["name"] for a in result["adapters"]] == ["Wi-Fi", "乙太網路"]
    assert result["adapters"][1]["global_ipv6"] == "2001:b011::1"
    assert result["adapters"][1]["ipv6_enabled"] is True


def test_list_adapters_single_object_and_empty(monkeypatch):
    _mock_ps(monkeypatch, out="NRJSON:" + json.dumps(_adapter(), ensure_ascii=False))
    result = ipv6_guard.list_adapters()
    assert result["ok"] is True and len(result["adapters"]) == 1

    _mock_ps(monkeypatch, out="NRJSON:[]")
    result = ipv6_guard.list_adapters()
    assert result["ok"] is True and result["adapters"] == []


def test_list_adapters_failures(monkeypatch):
    _mock_ps(monkeypatch, rc=1, err="Access is denied")
    r = ipv6_guard.list_adapters()
    assert r["ok"] is False and "Access is denied" in r["error"]

    _mock_ps(monkeypatch, out="no marker here")
    r = ipv6_guard.list_adapters()
    assert r["ok"] is False and "未回傳網卡清單" in r["error"]

    _mock_ps(monkeypatch, out="NRJSON:{broken")
    r = ipv6_guard.list_adapters()
    assert r["ok"] is False and "解析失敗" in r["error"]


def test_non_windows_never_calls_powershell(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("非 Windows 不應呼叫外部命令")

    monkeypatch.setattr(ipv6_guard.sys, "platform", "linux")
    monkeypatch.setattr(ipv6_guard, "_run_powershell", fail)
    assert ipv6_guard.list_adapters()["error"] == "unsupported platform"
    assert ipv6_guard.set_binding(["X"], False)["error"] == "unsupported platform"


def test_list_adapters_handles_oserror(monkeypatch):
    monkeypatch.setattr(ipv6_guard.sys, "platform", "win32")

    def boom(script):
        raise OSError("powershell not found")

    monkeypatch.setattr(ipv6_guard, "_run_powershell", boom)
    assert "powershell not found" in ipv6_guard.list_adapters()["error"]


# ---------------------------------------------------------------- 綁定變更

def test_set_binding_parses_all_result_kinds(monkeypatch):
    out = "\n".join([
        "OK|乙太網路|True|False",
        "OK|Wi-Fi|False|False",
        "NOBINDING|Gone NIC",
        "ERROR|Broken NIC|Access is denied",
    ])
    monkeypatch.setattr(ipv6_guard.sys, "platform", "win32")
    captured = {}

    def fake_run(script):
        captured["script"] = script
        return (0, out, "")

    monkeypatch.setattr(ipv6_guard, "_run_powershell", fake_run)
    names = ["乙太網路", "Wi-Fi", "Gone NIC", "Broken NIC"]
    result = ipv6_guard.set_binding(names, False)
    assert result["ok"] is True
    assert "Disable-NetAdapterBinding" in captured["script"]
    b64 = captured["script"].split("FromBase64String('", 1)[1].split("')", 1)[0]
    payload = json.loads(base64.b64decode(b64).decode("utf-8"))
    assert payload == {"enabled": False, "names": names}
    assert result["changed"] == ["乙太網路"]
    assert [r["state"] for r in result["results"]] == [
        "ok", "ok", "nobinding", "error"]
    assert result["results"][3]["message"] == "Access is denied"


def test_set_binding_empty_names_is_noop(monkeypatch):
    def fail(*a, **k):
        raise AssertionError("空清單不該呼叫 PowerShell")

    monkeypatch.setattr(ipv6_guard, "_run_powershell", fail)
    result = ipv6_guard.set_binding([], False)
    assert result["ok"] is True and result["results"] == []


def test_set_binding_command_failure(monkeypatch):
    _mock_ps(monkeypatch, rc=1, err="Access is denied")
    r = ipv6_guard.set_binding(["乙太網路"], False)
    assert r["ok"] is False and "Access is denied" in r["error"]


# ---------------------------------------------------------------- 狀態/還原

def test_default_and_normalize_state():
    assert ipv6_guard.default_state() == {
        "enabled": False, "adapters": [], "original": {},
        "restore_on_exit": False,
    }
    assert ipv6_guard.normalize_state(None) == ipv6_guard.default_state()
    assert ipv6_guard.normalize_state("garbage") == ipv6_guard.default_state()
    bad = ipv6_guard.normalize_state({
        "enabled": "yes", "adapters": "not-a-list", "original": 7,
        "restore_on_exit": 1,
    })
    assert bad["enabled"] is True
    assert bad["adapters"] == [] and bad["original"] == {}
    assert bad["restore_on_exit"] is True


def test_plan_restore_only_enables_originally_enabled():
    state = {
        "enabled": True,
        "adapters": ["乙太網路", "Wi-Fi"],
        # Wi-Fi 是使用者自己關的，還原時不能把它打開
        "original": {"乙太網路": True, "Wi-Fi": False},
        "restore_on_exit": False,
    }
    assert ipv6_guard.plan_restore(state) == ["乙太網路"]


def test_plan_restore_falls_back_to_adapters_when_record_lost():
    state = {"enabled": True, "adapters": ["乙太網路"], "original": {}}
    assert ipv6_guard.plan_restore(state) == ["乙太網路"]


def test_merge_original_keeps_first_snapshot_while_protected():
    current = [
        {"name": "乙太網路", "ipv6_enabled": False},
        {"name": "Wi-Fi", "ipv6_enabled": False},
    ]
    previous = {"乙太網路": True}
    merged = ipv6_guard.merge_original(
        previous, current, ["乙太網路", "Wi-Fi"], True)
    # 乙太網路必須保留 True (否則還原時什麼都不會啟用)
    assert merged == {"乙太網路": True, "Wi-Fi": False}
    # 防護未啟用時重新抓取
    fresh = ipv6_guard.merge_original(previous, current, ["乙太網路"], False)
    assert fresh == {"乙太網路": False}


def test_capture_original_ignores_unknown_adapters():
    assert ipv6_guard.capture_original(
        [_adapter()], ["乙太網路", "不存在"]) == {"乙太網路": True}


def test_restore_state_success_and_failure():
    state = {
        "enabled": True, "adapters": ["乙太網路", "Wi-Fi"],
        "original": {"乙太網路": True, "Wi-Fi": False},
        "restore_on_exit": True,
    }
    captured = {}

    def ok_setter(names, enabled):
        captured["names"] = names
        captured["enabled"] = enabled
        return {"ok": True, "results": [{"name": names[0], "state": "ok"}],
                "changed": names}

    new_state, res = ipv6_guard.restore_state(state, setter=ok_setter)
    assert captured == {"names": ["乙太網路"], "enabled": True}
    assert new_state["enabled"] is False and new_state["original"] == {}

    def fail_setter(names, enabled):
        return {"ok": False, "error": "Access is denied", "results": []}

    kept, res = ipv6_guard.restore_state(state, setter=fail_setter)
    # 失敗時必須保留原始紀錄，下次啟動才能再還原
    assert kept["enabled"] is True
    assert kept["original"] == {"乙太網路": True, "Wi-Fi": False}


def test_restore_state_noop_when_nothing_to_restore():
    def fail(*a, **k):
        raise AssertionError("沒有網卡要還原時不該呼叫 setter")

    new_state, res = ipv6_guard.restore_state(
        ipv6_guard.default_state(), setter=fail)
    assert res.get("noop") is True and new_state["enabled"] is False


def test_is_active():
    state = {"enabled": True, "adapters": ["乙太網路"], "original": {}}
    assert ipv6_guard.is_active(state) is True
    assert ipv6_guard.is_active(state, [_adapter("乙太網路", True)]) is False
    assert ipv6_guard.is_active(state, [_adapter("乙太網路", False)]) is True
    state["enabled"] = False
    assert ipv6_guard.is_active(state) is False
