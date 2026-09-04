# -*- coding: utf-8 -*-
"""模組化回歸測試 — 防止 mixin 缺 import 導致執行期 NameError"""
import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_all_modules_importable():
    for mod in ["app_helpers", "config_store", "rule_utils",
                "tabs_hub", "tabs_rules", "tabs_proxies", "tabs_monitor",
                "tabs_vpngate", "vpngate", "vpn_history"]:
        importlib.import_module(mod)


def test_mixin_modules_have_cross_module_names():
    """mixin 方法用到的跨模組名稱必須在其模組 globals 可解析。

    回歸案例: test_all_proxies 呼叫 check_proxy_connection,
    但 tabs_proxies.py 漏 import 導致 NameError。
    """
    tabs_proxies = importlib.import_module("tabs_proxies")
    assert callable(tabs_proxies.check_proxy_connection)

    # 每個 mixin 都需要 tr / proxy_core / Qt 元件 (它們的方法會用到)
    for mod in ["tabs_hub", "tabs_rules", "tabs_proxies", "tabs_monitor"]:
        m = importlib.import_module(mod)
        assert hasattr(m, "tr")
        assert hasattr(m, "proxy_core")
        assert hasattr(m, "Qt")


def test_no_undefined_names_in_mixins():
    """以 pyflakes 靜態掃描 mixin 檔案, 確認無 undefined name (F821)。"""
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = ["IntegratedApp.py", "app_helpers.py", "config_store.py", "rule_utils.py",
             "tabs_hub.py", "tabs_rules.py", "tabs_proxies.py", "tabs_monitor.py",
             "tabs_vpngate.py", "vpngate.py", "vpn_history.py"]
    r = subprocess.run(
        [sys.executable, "-m", "pyflakes", *[os.path.join(repo, f) for f in files]],
        capture_output=True, text=True,
    )
    # pyflakes 對 undefined name 輸出 "undefined name 'xxx'"
    undefined = [ln for ln in r.stdout.splitlines() if "undefined name" in ln]
    assert not undefined, f"發現 undefined name:\n" + "\n".join(undefined)


def test_mainwindow_inherits_all_mixins():
    from IntegratedApp import MainWindow
    from tabs_hub import HubTabMixin
    from tabs_rules import RulesTabMixin
    from tabs_proxies import ProxiesTabMixin
    from tabs_monitor import MonitorTabMixin
    from tabs_vpngate import VpnGateTabMixin
    assert issubclass(MainWindow, HubTabMixin)
    assert issubclass(MainWindow, RulesTabMixin)
    assert issubclass(MainWindow, ProxiesTabMixin)
    assert issubclass(MainWindow, MonitorTabMixin)
    assert issubclass(MainWindow, VpnGateTabMixin)
