# -*- coding: utf-8 -*-
"""control_api 單元測試 — 本機控制 API 的端點、token 驗證與去重。

以 port=0 讓系統指派埠，並以 dispatch 同步執行 (不需要 Qt / UI 執行緒)，
驗證 HTTP 層與後端呼叫的契約。
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import control_api  # noqa: E402


class FakeBackend:
    """模擬 MainWindow 的規則後端，只保留 API 需要的最小行為。"""

    def __init__(self):
        self.rules = []

    def ping(self):
        return {"app": "NetRedirector", "version": "test", "running": False}

    def list_rules(self, target=None):
        want = (target or "").lower()
        return [r for r in self.rules
                if not want or r["target"].lower() == want]

    def ensure_direct(self, target):
        for r in self.rules:
            if r["target"].lower() == target.lower() and r["action_key"] == 1:
                return {"added": False, "existed": True, "rule_id": r["id"]}
        rid = len(self.rules) + 1
        self.rules.append(
            {"id": rid, "target": target, "action_key": 1, "enabled": True})
        return {"added": True, "existed": False, "rule_id": rid}


def _start(backend, token=None):
    server = control_api.ControlApiServer(
        dispatch=lambda fn: fn(),
        ping_fn=backend.ping,
        list_rules_fn=backend.list_rules,
        ensure_direct_fn=backend.ensure_direct,
        port=0, token=token)
    assert server.start() is True
    return server


def _request(server, path, method="GET", payload=None, token=None):
    url = f"http://127.0.0.1:{server.actual_port}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token is not None:
        req.add_header("X-NR-Token", token)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def test_ping_returns_backend_payload():
    server = _start(FakeBackend())
    try:
        status, body = _request(server, "/ping")
        assert status == 200
        assert body["app"] == "NetRedirector"
        assert body["version"] == "test"
    finally:
        server.stop()


def test_ensure_direct_adds_then_is_idempotent():
    backend = FakeBackend()
    server = _start(backend)
    try:
        status, body = _request(
            server, "/ensure-direct", method="POST",
            payload={"target": "MultiSocksDownloader.exe"})
        assert status == 200
        assert body == {"added": True, "existed": False, "rule_id": 1}

        # 第二次呼叫不得再新增一條 (C 核心 AddRule 不去重，重複會堆規則)
        status, body = _request(
            server, "/ensure-direct", method="POST",
            payload={"target": "MultiSocksDownloader.exe"})
        assert body["added"] is False
        assert body["existed"] is True
        assert len(backend.rules) == 1
    finally:
        server.stop()


def test_list_rules_filters_by_target():
    backend = FakeBackend()
    backend.rules.append({"id": 1, "target": "chrome.exe", "action_key": 0})
    backend.rules.append({"id": 2, "target": "curl.exe", "action_key": 1})
    server = _start(backend)
    try:
        _, body = _request(server, "/rules")
        assert len(body["rules"]) == 2

        _, body = _request(server, "/rules?target=curl.exe")
        assert len(body["rules"]) == 1
        assert body["rules"][0]["target"] == "curl.exe"
    finally:
        server.stop()


def test_ensure_direct_requires_target():
    server = _start(FakeBackend())
    try:
        try:
            _request(server, "/ensure-direct", method="POST", payload={})
            raise AssertionError("缺 target 應該要 400")
        except urllib.error.HTTPError as e:
            assert e.code == 400
    finally:
        server.stop()


def test_unknown_path_returns_404():
    server = _start(FakeBackend())
    try:
        try:
            _request(server, "/nope")
            raise AssertionError("未知路徑應該要 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        server.stop()


def test_token_required_when_set():
    server = _start(FakeBackend(), token="s3cr3t")
    try:
        # 沒帶 token → 401
        try:
            _request(server, "/ping")
            raise AssertionError("缺 token 應該要 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401

        # 帶對的 token → 200
        status, body = _request(server, "/ping", token="s3cr3t")
        assert status == 200
        assert body["app"] == "NetRedirector"
    finally:
        server.stop()


def test_stop_is_idempotent():
    server = _start(FakeBackend())
    server.stop()
    server.stop()  # 重複呼叫不得拋錯


def test_load_or_create_token_is_stable(tmp_path):
    path = str(tmp_path / "control.token")
    first = control_api.load_or_create_token(path)
    assert first
    assert control_api.load_or_create_token(path) == first


def test_is_generic_interpreter_detects_python_family():
    for name in ("python.exe", "pythonw.exe", "py.exe", "Python.EXE",
                 "python3.exe", "python3.11.exe"):
        assert control_api.is_generic_interpreter(name), name


def test_is_generic_interpreter_rejects_specific_names():
    for name in ("MultiSocksDownloader.exe", "chrome.exe", "mypython.exe",
                 "python_tool.exe", ""):
        assert not control_api.is_generic_interpreter(name), name
