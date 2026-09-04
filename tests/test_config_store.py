# -*- coding: utf-8 -*-
"""config_store 單元測試 — 設定序列化 (DPAPI 加密) 與檔案 I/O"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config_store
import secure_config


def sample_state():
    proxies = [
        {"name": "P1", "type": "SOCKS5", "ip": "127.0.0.1", "port": 1080,
         "user": "u", "pass": "secret123", "latency": "-"},
        {"name": "P2", "type": "HTTP", "ip": "1.2.3.4", "port": 3128,
         "user": "", "pass": "", "latency": "5"},
    ]
    rules = [
        {"type": "Name", "target": "chrome.exe", "hosts": "*", "ports": "*",
         "proto": "BOTH", "action": "PROXY (轉發)", "action_key": 0,
         "proxy": "[Custom] P1", "proxy_name": "P1"},
        {"type": "PID", "target": "1234", "hosts": "8.8.8.8", "ports": "443",
         "proto": "TCP", "action": "DIRECT (直連)", "action_key": 1,
         "proxy": "Direct"},
    ]
    return proxies, rules


def test_build_config_data_structure():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "1.1.1.1", False, {1080: ["A"]}, proxies, rules)
    assert data["lang"] == "zh_TW"
    assert data["ping_target"] == "1.1.1.1"
    assert data["hubs"] == {1080: ["A"]}
    assert len(data["proxies"]) == 2
    assert len(data["rules"]) == 2


def test_proxy_password_dpapi_encrypted():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules)
    enc = data["proxies"][0]["pass"]
    assert enc.startswith(secure_config.PREFIX)
    assert "secret123" not in enc
    # 解密可還原
    assert secure_config.decrypt_password(enc) == "secret123"
    # 空密碼保持空字串
    assert data["proxies"][1]["pass"] == ""


def test_rules_preserve_ui_fields():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules)
    r = data["rules"][0]
    assert r["proxy_text"] == "[Custom] P1"
    assert r["target"] == "chrome.exe"
    assert r["action_key"] == 0
    assert r["hosts"] == "*"


def test_rules_persist_proxy_name():
    """proxy_name (穩定識別) 必須持久化;舊規則無此欄位時存空字串。"""
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules)
    assert data["rules"][0]["proxy_name"] == "P1"
    # sample_state 第二條規則沒有 proxy_name → 序列化為空字串 (向後相容)
    assert data["rules"][1]["proxy_name"] == ""


def test_dynamic_fields_removed():
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules)
    # latency / id 不得出現在序列化結果
    assert "latency" not in data["proxies"][0]
    assert "id" not in data["proxies"][0]


def test_save_and_load_roundtrip(tmp_path):
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "8.8.8.8", False, {}, proxies, rules)
    path = os.path.join(tmp_path, "config.json")
    assert config_store.save_config_file(path, data) is None
    loaded = config_store.load_config_file(path)
    assert loaded is not None
    assert loaded["proxies"][0]["name"] == "P1"
    assert secure_config.decrypt_password(loaded["proxies"][0]["pass"]) == "secret123"
    assert loaded["rules"][1]["type"] == "PID"
    assert loaded["ping_target"] == "8.8.8.8"


def test_load_missing_file_returns_none(tmp_path):
    assert config_store.load_config_file(os.path.join(tmp_path, "nope.json")) is None


def test_load_corrupt_file_returns_none(tmp_path):
    path = os.path.join(tmp_path, "bad.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not valid json")
    assert config_store.load_config_file(path) is None


def test_load_corrupt_file_backed_up(tmp_path):
    """氈損檔案必須被改名保留為 .corrupt.bak,原始內容不可遺失。"""
    path = os.path.join(tmp_path, "bad.json")
    original = "{not valid json"
    with open(path, "w", encoding="utf-8") as f:
        f.write(original)
    assert config_store.load_config_file(path) is None
    bak = path + ".corrupt.bak"
    assert os.path.exists(bak)
    with open(bak, encoding="utf-8") as f:
        assert f.read() == original
    # 原檔已改名,目錄中不再有壞檔 (之後存檔可安全寫入新檔)
    assert not os.path.exists(path)


def test_load_corrupt_backup_overwritten_on_new_corruption(tmp_path):
    """再次遇到氈損時,舊 .bak 被替換成最新的氈損內容。"""
    path = os.path.join(tmp_path, "bad.json")
    bak = path + ".corrupt.bak"
    with open(path, "w", encoding="utf-8") as f:
        f.write("{first")
    config_store.load_config_file(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("{second corruption")
    config_store.load_config_file(path)
    with open(bak, encoding="utf-8") as f:
        assert f.read() == "{second corruption"


def test_load_locked_file_not_treated_as_corrupt(tmp_path, monkeypatch):
    """讀取失敗 (PermissionError, 如防毒短暫鎖檔) 不得誤判成氈損把好檔搬走。"""
    import builtins
    path = os.path.join(tmp_path, "locked.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write('{"lang": "zh_TW"}')
    real_open = builtins.open

    def fake_open(p, *a, **k):
        if os.path.abspath(str(p)) == os.path.abspath(path):
            raise PermissionError(13, "Permission denied (simulated AV lock)")
        return real_open(p, *a, **k)

    monkeypatch.setattr(builtins, "open", fake_open)
    assert config_store.load_config_file(path) is None
    # 檔案完好留在原地, 沒有被改名成 .corrupt.bak
    assert os.path.exists(path)
    assert not os.path.exists(path + ".corrupt.bak")


def test_save_is_atomic_no_tmp_left_behind(tmp_path):
    """存檔後不得殘留暫存檔;目標檔內容完整。"""
    path = os.path.join(tmp_path, "config.json")
    assert config_store.save_config_file(path, {"a": 1}) is None
    assert not os.path.exists(path + ".tmp")
    with open(path, encoding="utf-8") as f:
        assert json.load(f) == {"a": 1}
    # 覆寫既有檔案亦然
    assert config_store.save_config_file(path, {"a": 2}) is None
    with open(path, encoding="utf-8") as f:
        assert json.load(f) == {"a": 2}


def test_save_to_bad_path_returns_error():
    err = config_store.save_config_file("Z:/no/such/dir/config.json", {})
    assert err is not None


def test_check_updates_default_and_roundtrip(tmp_path):
    """check_updates 預設開啟、可關閉，且序列化往返保留。"""
    proxies, rules = sample_state()
    data = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules)
    assert data["check_updates"] is True

    data_off = config_store.build_config_data("zh_TW", "", False, {}, proxies, rules, False)
    assert data_off["check_updates"] is False

    path = os.path.join(tmp_path, "config.json")
    assert config_store.save_config_file(path, data_off) is None
    assert config_store.load_config_file(path)["check_updates"] is False

