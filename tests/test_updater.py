# -*- coding: utf-8 -*-
"""updater 純邏輯單元測試 — 版本比對 / SHA256 校驗 (不觸及網路)。"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import updater


def test_parse_semver_strips_v():
    assert updater.parse_semver("v1.7.0") == "1.7.0"
    assert updater.parse_semver("1.7.0") == "1.7.0"
    assert updater.parse_semver("") == ""


def test_version_tuple_ordering():
    # 字串比對會誤判 1.10.0 < 1.9.0，tuple 比對不會
    assert updater._version_tuple("1.10.0") > updater._version_tuple("1.9.0")
    assert updater._version_tuple("1.6.1") == updater._version_tuple("1.6.1")


def test_check_update_none_when_same_or_older(monkeypatch):
    monkeypatch.setattr(
        updater, "get_latest_release",
        lambda *a, **k: {"tag_name": "v1.6.1", "assets": []})
    # 同版本 → None (不會因缺資產而拋錯)
    assert updater.check_update("1.6.1") is None

    monkeypatch.setattr(
        updater, "get_latest_release",
        lambda *a, **k: {"tag_name": "v1.5.0", "assets": []})
    # 較舊 → None
    assert updater.check_update("1.6.1") is None


def test_verify_sha256(tmp_path):
    p = tmp_path / "f.bin"
    data = b"hello netredirector"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert updater.verify_sha256(str(p), expected)
    assert updater.verify_sha256(str(p), expected.upper())  # 大小寫不敏感
    assert not updater.verify_sha256(str(p), "0" * 64)


def test_parse_expected_sha256():
    text = "abc123  NetRedirector-v1.6.2-win64.zip\n"
    assert updater._parse_expected_sha256(text, "NetRedirector-v1.6.2-win64.zip") == "abc123"
    assert updater._parse_expected_sha256(text, "nonexistent.zip") is None


def test_is_frozen_detects_nuitka_compiled(monkeypatch):
    """Nuitka 以 __compiled__ 注入凍結旗標，is_frozen() 必須能辨識。"""
    monkeypatch.setattr(updater, "__compiled__", True, raising=False)
    assert updater.is_frozen() is True

    monkeypatch.setattr(updater, "__compiled__", False, raising=False)
    assert updater.is_frozen() is False

