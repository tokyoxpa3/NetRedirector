# -*- coding: utf-8 -*-
"""vpn_history 單元測試 — 去重、穩定度評分、汰除與檔案 I/O"""
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import vpn_history


def make_node(ip, score=100, port=5555, country_long="Japan", country_short="JP"):
    return SimpleNamespace(
        hostname="vpngate-test",
        ip=ip,
        score=score,
        ping_ms=10,
        speed_bps=50_000_000,
        country_long=country_long,
        country_short=country_short,
        num_sessions=5,
        port=port,
    )


def empty_history():
    return {"version": 1, "nodes": {}}


def test_upsert_dedup_by_ip():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4", score=100))
    vpn_history.upsert_node(h, make_node("1.2.3.4", score=200))  # 同 ip 再來一次
    assert len(h["nodes"]) == 1
    rec = h["nodes"]["1.2.3.4"]
    # 快照欄位被更新為最新
    assert rec["last_score"] == 200
    # 累積統計未被重設
    assert rec["connect_attempts"] == 0


def test_upsert_two_ips_kept_separate():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.1.1.1"))
    vpn_history.upsert_node(h, make_node("2.2.2.2"))
    assert set(h["nodes"]) == {"1.1.1.1", "2.2.2.2"}


def test_record_connect_success_resets_failures():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    vpn_history.record_connect(h, "1.2.3.4", ok=False)  # 失敗
    rec = h["nodes"]["1.2.3.4"]
    assert rec["consecutive_failures"] == 1
    assert rec["connect_attempts"] == 1
    assert rec["connect_successes"] == 0
    # 成功後歸零
    vpn_history.record_connect(h, "1.2.3.4", ok=True, tunnel_ok=True)
    assert rec["consecutive_failures"] == 0
    assert rec["connect_successes"] == 1
    assert rec["tunnel_checks"] == 1
    assert rec["tunnel_ok"] == 1


def test_record_connect_tunnel_fail():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    vpn_history.record_connect(h, "1.2.3.4", ok=True, tunnel_ok=False)
    rec = h["nodes"]["1.2.3.4"]
    assert rec["tunnel_checks"] == 1
    assert rec["tunnel_ok"] == 0


def test_record_connect_untested_tunnel():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    vpn_history.record_connect(h, "1.2.3.4", ok=True, tunnel_ok=None)
    rec = h["nodes"]["1.2.3.4"]
    assert rec["tunnel_checks"] == 0


def test_record_session_accumulates_duration():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    vpn_history.record_session(h, "1.2.3.4", 3600)
    vpn_history.record_session(h, "1.2.3.4", 1800)
    rec = h["nodes"]["1.2.3.4"]
    assert rec["session_count"] == 2
    assert rec["total_connected_seconds"] == 5400


def test_record_disconnect_increments():
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    vpn_history.record_disconnect(h, "1.2.3.4")
    vpn_history.record_disconnect(h, "1.2.3.4")
    assert h["nodes"]["1.2.3.4"]["disconnect_count"] == 2


def test_stability_cold_start_neutral():
    assert vpn_history.stability({}) == 0.5
    assert vpn_history.stability({"connect_attempts": 0}) == 0.5


def test_stability_success_ranks_above_failure():
    good = {"connect_attempts": 10, "connect_successes": 10,
            "tunnel_checks": 10, "tunnel_ok": 10,
            "session_count": 5, "total_connected_seconds": 18000,
            "disconnect_count": 0, "consecutive_failures": 0}
    bad = {"connect_attempts": 10, "connect_successes": 2,
           "tunnel_checks": 2, "tunnel_ok": 0,
           "session_count": 2, "total_connected_seconds": 60,
           "disconnect_count": 8, "consecutive_failures": 3}
    assert vpn_history.stability(good) > vpn_history.stability(bad)


def test_stability_bounded_0_1():
    extreme = {"connect_attempts": 1, "connect_successes": 0,
               "tunnel_checks": 0, "tunnel_ok": 0,
               "session_count": 0, "total_connected_seconds": 0,
               "disconnect_count": 999, "consecutive_failures": 999}
    val = vpn_history.stability(extreme)
    assert 0.0 <= val <= 1.0


def test_stability_kick_penalty():
    base = {"connect_attempts": 10, "connect_successes": 10,
            "tunnel_checks": 10, "tunnel_ok": 10,
            "session_count": 1, "total_connected_seconds": 3600,
            "consecutive_failures": 0, "disconnect_count": 0}
    kicked = dict(base, disconnect_count=10)
    assert vpn_history.stability(kicked) < vpn_history.stability(base)


def test_prune_removes_stale():
    h = empty_history()
    old = _empty_with_last_seen(int(time.time()) - 40 * 86400)
    fresh = _empty_with_last_seen(int(time.time()))
    h["nodes"] = {"old": old, "fresh": fresh}
    vpn_history.prune(h, max_nodes=100, max_age_days=30)
    assert set(h["nodes"]) == {"fresh"}


def test_prune_respects_max_nodes():
    h = empty_history()
    for i in range(10):
        ip = f"10.0.0.{i}"
        rec = vpn_history.upsert_node(h, make_node(ip))
        rec["connect_attempts"] = 1
        rec["connect_successes"] = 0 if i < 5 else 1  # 後 5 個較穩
    vpn_history.prune(h, max_nodes=5, max_age_days=9999)
    assert len(h["nodes"]) == 5
    # 較穩的 (i>=5) 應被保留
    kept_ips = set(h["nodes"])
    assert "10.0.0.9" in kept_ips
    assert "10.0.0.0" not in kept_ips


def test_save_and_load_roundtrip(tmp_path):
    path = os.path.join(tmp_path, "vpn_history.json")
    h = empty_history()
    vpn_history.upsert_node(h, make_node("1.2.3.4"))
    assert vpn_history.save_history(path, h) is None
    loaded = vpn_history.load_history(path)
    assert loaded["nodes"]["1.2.3.4"]["ip"] == "1.2.3.4"


def test_load_missing_returns_empty():
    assert vpn_history.load_history("/nonexistent/vpn_history.json") == {
        "version": 1, "nodes": {}
    }


def test_load_corrupt_returns_empty_and_backs_up(tmp_path):
    path = os.path.join(tmp_path, "bad.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not valid json")
    loaded = vpn_history.load_history(path)
    assert loaded == {"version": 1, "nodes": {}}
    assert os.path.exists(path + ".corrupt.bak")


def test_load_non_dict_returns_empty(tmp_path):
    path = os.path.join(tmp_path, "arr.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("[1, 2, 3]")
    assert vpn_history.load_history(path) == {"version": 1, "nodes": {}}


def test_save_no_tmp_left(tmp_path):
    path = os.path.join(tmp_path, "vpn_history.json")
    assert vpn_history.save_history(path, empty_history()) is None
    assert not os.path.exists(path + ".tmp")


def _empty_with_last_seen(last_seen):
    rec = vpn_history._empty_record("0.0.0.0")
    rec["last_seen"] = last_seen
    return rec
