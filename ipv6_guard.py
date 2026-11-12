# -*- coding: utf-8 -*-
"""IPv6 防洩漏：停用「實體網卡」的 TCP/IPv6 協定綁定，並可精準還原。

背景
----
VPN Gate / SoftEther 公開節點是純 IPv4，伺服器端沒有 dual-stack RA，因此
本機不存在任何「日本端的 IPv6 位址」。即使 WinDivert 把 IPv6 封包攔下來、
規則也指定轉發到 Hub，Hub 連線時仍會查系統路由表：唯一的 ::/0 指向實體
網卡的 ISP router，封包就從真實所在地出去了 (IPv6 leak)。

在沒有日本 IPv6 出口的前提下，正確目標不是「偽造日本 IPv6」，而是
「零 IPv6 洩漏」：讓本機 IPv6 完全不通，瀏覽器的 Happy Eyeballs 會自動
退回 IPv4，全部流量走 VPN。做法就是對實體網卡執行
``Disable-NetAdapterBinding -ComponentID ms_tcpip6``，連 ICMPv6 / RA /
on-link IPv6 DNS 一起消失，比路由表或防火牆規則都乾淨。

為什麼不碰 VPN 虛擬網卡
------------------------
SoftEther 虛擬網卡本來就只有 link-local fe80::，沒有全球 IPv6，關掉它的
綁定沒有任何效果，還會讓 16 張網卡的清單難以閱讀。這裡用
``Get-NetAdapter -Physical`` 先濾掉所有虛擬裝置，再用關鍵字黑名單雙重
保險；-Physical 在某些驅動上可能誤判而回傳空清單，此時才退回
``Virtual -eq False`` 的全量列舉。

持久化與還原
------------
Disable/Enable-NetAdapterBinding 會寫入系統設定，**重開機仍然有效**。
所以不能無腦在還原時 Enable 全部網卡 —— 那會把使用者原本就自己關掉的
IPv6 打開。本模組因此提供：

* ``capture_original()`` / ``merge_original()``：記錄每張網卡被改動前的狀態
* ``plan_restore()``：只挑出「原本是啟用」的網卡 Enable
* ``normalize_state()``：從 config.json 還原狀態，缺欄位時給安全預設值

狀態由呼叫端 (IntegratedApp) 存進 config.json 的 ``ipv6_guard`` 欄位；
程式崩潰或被強制結束後，下次啟動仍可依該狀態還原。

編碼
----
網卡名稱可能是中文 («乙太網路») 甚至含引號，直接拼進 ``-Command`` 會
被 Windows 命令列編碼與 PowerShell 引號規則搞壞。這裡改用
``-EncodedCommand`` (UTF-16LE base64) 承載整段腳本，參數再以 UTF-8
base64 的 JSON 內嵌，PowerShell 端解碼後用 ConvertFrom-Json 取得陣列，
全程不拼接使用者資料到程式碼裡。

需要管理員權限；主程式載入 WinDivert 時已要求最高權限。
"""

import base64
import json
import subprocess
import sys

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_TIMEOUT = 30

# 即使 -Physical 已濾過，仍排除這些名稱/描述：有些虛擬介面會被驅動誤報為
# 實體，或使用者把 Wi-Fi 熱點/虛擬交換器接在主網卡上。一律不列出。
_VIRTUAL_KEYWORDS_PS = (
    "vpn", "tap", "tun", "wireguard", "openvpn", "softether",
    "vmware", "virtualbox", "hyper-v", "loopback", "pseudo",
    "miniport", "zerotier", "tailscale", "bluetooth", "teredo",
    "6to4", "isatap", "wan miniport",
)

_PS_LIST = r"""
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$bind = @{}
try {
    Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue |
        ForEach-Object { $bind[$_.Name] = [bool]$_.Enabled }
} catch {}

# 全球 IPv6 位址：有這個值的網卡就是「會洩漏」的那一張，供 UI 標示。
$v6 = @{}
try {
    Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressState -eq 'Preferred' -and
                       $_.IPAddress -notlike 'fe80*' -and
                       $_.IPAddress -ne '::1' -and
                       $_.PrefixOrigin -ne 'WellKnown' } |
        ForEach-Object {
            if (-not $v6.ContainsKey($_.InterfaceAlias)) {
                $v6[$_.InterfaceAlias] = $_.IPAddress
            }
        }
} catch {}

$patterns = @(__KEYWORDS__)
$ads = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue)
if ($ads.Count -eq 0) {
    $ads = @(Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Virtual })
}

$rows = @()
foreach ($ad in $ads) {
    $key = ([string]$ad.Name + ' ' + [string]$ad.InterfaceDescription).ToLowerInvariant()
    $skip = $false
    foreach ($p in $patterns) {
        if ($key.Contains($p)) { $skip = $true; break }
    }
    if ($skip) { continue }
    # 沒有 ms_tcpip6 綁定的網卡本來就沒有 IPv6 可關，不必列出
    if (-not $bind.ContainsKey($ad.Name)) { continue }
    $g6 = ''
    if ($v6.ContainsKey($ad.Name)) { $g6 = [string]$v6[$ad.Name] }
    $rows += [ordered]@{
        name          = [string]$ad.Name
        description   = [string]$ad.InterfaceDescription
        status        = [string]$ad.Status
        if_index      = [int]$ad.ifIndex
        ipv6_enabled  = [bool]$bind[$ad.Name]
        global_ipv6   = $g6
    }
}
Write-Output ('NRJSON:' + (ConvertTo-Json -InputObject @($rows) -Compress -Depth 4))
"""

_PS_SET = r"""
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$payload = ConvertFrom-Json -InputObject (
    [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String('__PAYLOAD_B64__')))
$wantEnabled = [bool]$payload.enabled
$names = @($payload.names)

foreach ($n in $names) {
    $n = [string]$n
    try {
        $b = Get-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        if (-not $b) { Write-Output ('NOBINDING|' + $n); continue }
        $before = [bool]$b.Enabled
        if ($before -ne $wantEnabled) {
            if ($wantEnabled) {
                Enable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction Stop
            } else {
                Disable-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction Stop
            }
        }
        $afterB = Get-NetAdapterBinding -Name $n -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
        $after = if ($afterB) { [bool]$afterB.Enabled } else { '' }
        Write-Output ('OK|' + $n + '|' + $before + '|' + $after)
    } catch {
        $msg = [string]$_.Exception.Message
        $msg = $msg.Replace("`r", ' ').Replace("`n", ' ').Replace('|', '/')
        Write-Output ('ERROR|' + $n + '|' + $msg)
    }
}
"""


def _keywords_ps():
    return ", ".join("'{}'".format(k) for k in _VIRTUAL_KEYWORDS_PS)


def _build_list_script():
    return _PS_LIST.replace("__KEYWORDS__", _keywords_ps())


def _build_set_script(names, enabled):
    """把網卡名稱與目標狀態包成 UTF-8 JSON → base64，避免任何引號/編碼問題。"""
    payload = json.dumps(
        {"enabled": bool(enabled), "names": [str(n) for n in names]},
        ensure_ascii=False,
    )
    b64 = base64.b64encode(payload.encode("utf-8")).decode("ascii")
    return _PS_SET.replace("__PAYLOAD_B64__", b64)


def _run_powershell(script):
    """以 -EncodedCommand 執行 PowerShell，回傳 (returncode, stdout, stderr)。"""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    proc = subprocess.run(
        [
            "powershell", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded,
        ],
        capture_output=True,
        timeout=_TIMEOUT,
        creationflags=_CREATE_NO_WINDOW,
    )
    return (
        proc.returncode,
        (proc.stdout or b"").decode("utf-8", errors="replace"),
        (proc.stderr or b"").decode("utf-8", errors="replace"),
    )


def is_supported():
    return sys.platform.startswith("win")


def list_adapters():
    """列舉可操作的實體網卡 (VPN 虛擬網卡不會出現在結果中)。

    回傳 dict:
        ok        是否成功
        adapters  list[dict]: name/description/status/if_index/
                  ipv6_enabled/global_ipv6
        error     失敗原因 (成功為 None)
    """
    result = {"ok": False, "adapters": [], "error": None}
    if not is_supported():
        result["error"] = "unsupported platform"
        return result
    try:
        rc, out, err = _run_powershell(_build_list_script())
    except (OSError, subprocess.SubprocessError) as e:
        result["error"] = str(e)
        return result
    if rc != 0:
        result["error"] = err.strip() or "powershell rc={}".format(rc)
        return result

    marker = "NRJSON:"
    payload = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(marker):
            payload = line[len(marker):].strip()
            break
    if payload is None:
        result["error"] = (err.strip() or "PowerShell 未回傳網卡清單").strip()
        return result
    try:
        parsed = json.loads(payload)
    except (ValueError, TypeError) as e:
        result["error"] = "網卡清單解析失敗: {}".format(e)
        return result
    if isinstance(parsed, dict):
        parsed = [parsed]
    if not isinstance(parsed, list):
        result["error"] = "網卡清單格式不符"
        return result

    adapters = []
    for raw in parsed:
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name", "")).strip()
        if not name:
            continue
        adapters.append({
            "name": name,
            "description": str(raw.get("description", "") or ""),
            "status": str(raw.get("status", "") or ""),
            "if_index": raw.get("if_index", 0),
            "ipv6_enabled": bool(raw.get("ipv6_enabled", False)),
            "global_ipv6": str(raw.get("global_ipv6", "") or ""),
        })
    adapters.sort(key=lambda a: a["name"])
    result["ok"] = True
    result["adapters"] = adapters
    return result


def set_binding(names, enabled):
    """對指定網卡啟用/停用 ms_tcpip6 綁定 (冪等，已是目標狀態就跳過)。

    回傳 dict:
        ok        PowerShell 是否成功執行 (個別網卡失敗記在 results)
        results   list[dict]: name/state(ok|nobinding|error)/before/after/message
        changed   實際被改變狀態的網卡名稱
        error     整體失敗原因 (成功為 None)
    """
    result = {"ok": False, "results": [], "changed": [], "error": None}
    names = [str(n).strip() for n in (names or []) if str(n).strip()]
    if not names:
        result["ok"] = True
        return result
    if not is_supported():
        result["error"] = "unsupported platform"
        return result
    try:
        rc, out, err = _run_powershell(_build_set_script(names, enabled))
    except (OSError, subprocess.SubprocessError) as e:
        result["error"] = str(e)
        return result
    if rc != 0:
        result["error"] = err.strip() or "powershell rc={}".format(rc)
        return result

    for line in out.splitlines():
        line = line.strip()
        if not line.startswith(("OK|", "NOBINDING|", "ERROR|")):
            continue
        parts = line.split("|", 3)
        tag = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        if tag == "OK":
            before = parts[2] if len(parts) > 2 else ""
            after = parts[3] if len(parts) > 3 else ""
            entry = {
                "name": name, "state": "ok",
                "before": before == "True", "after": after == "True",
                "message": "",
            }
            if before != after:
                result["changed"].append(name)
        elif tag == "NOBINDING":
            entry = {
                "name": name, "state": "nobinding",
                "before": None, "after": None,
                "message": "找不到 ms_tcpip6 綁定",
            }
        else:
            entry = {
                "name": name, "state": "error",
                "before": None, "after": None,
                "message": parts[2] if len(parts) > 2 else "",
            }
        result["results"].append(entry)

    # 權限不足等情況下 PowerShell 可能 rc=0 但完全沒有輸出
    if not result["results"] and err.strip():
        result["error"] = err.strip()
        return result
    result["ok"] = True
    return result


# --------------------------------------------------------------- 狀態管理

def default_state():
    """config.json 中 ``ipv6_guard`` 的安全預設值 (防護關閉)。"""
    return {
        "enabled": False,
        "adapters": [],
        "original": {},
        "restore_on_exit": False,
    }


def normalize_state(raw):
    """把設定檔讀到的任意內容正规化，缺欄位/壞型別都給安全預設值。"""
    state = default_state()
    if not isinstance(raw, dict):
        return state
    state["enabled"] = bool(raw.get("enabled", False))
    adapters = raw.get("adapters", [])
    if isinstance(adapters, (list, tuple)):
        state["adapters"] = [
            str(x).strip() for x in adapters if str(x).strip()]
    original = raw.get("original", {})
    if isinstance(original, dict):
        state["original"] = {
            str(k): bool(v) for k, v in original.items() if str(k).strip()}
    state["restore_on_exit"] = bool(raw.get("restore_on_exit", False))
    return state


def capture_original(adapters, names):
    """記錄網卡「被改動前」的 IPv6 綁定狀態；查不到的網卡不列入。"""
    by_name = {a["name"]: a for a in (adapters or []) if a.get("name")}
    return {
        n: bool(by_name[n].get("ipv6_enabled", False))
        for n in names if n in by_name
    }


def merge_original(previous, adapters, names, guard_enabled):
    """防護已啟用時，保留第一次記錄的原始狀態，只為新加入的網卡補記錄。

    若在防護中重新按「啟用防護」，直接重抓會把所有網卡記成 False，
    之後還原就什麼都不做 → IPv6 永久被關掉。所以舊值必須保留。
    """
    if not guard_enabled:
        return capture_original(adapters, names)
    merged = dict(previous or {})
    for name, was_enabled in capture_original(adapters, names).items():
        merged.setdefault(name, was_enabled)
    return merged


def plan_restore(state):
    """回傳還原時需要 Enable 的網卡清單。

    有原始狀態紀錄 → 只啟用「原本就是啟用」的網卡 (使用者自己關掉的不動)；
    紀錄遺失 → 退回對所有已記錄網卡 Enable，呼叫端應先向使用者確認。
    """
    state = normalize_state(state)
    if state["original"]:
        return [n for n, was in state["original"].items() if was]
    return list(state["adapters"])


def is_active(state, adapters=None):
    """目前是否仍有任何網卡的 IPv6 被我們停用 (供啟動重新套用 / 關閉提醒)。"""
    state = normalize_state(state)
    if not state["enabled"] or not state["adapters"]:
        return False
    if adapters is None:
        return True
    by_name = {a["name"]: a for a in adapters if a.get("name")}
    return any(
        not by_name[n]["ipv6_enabled"]
        for n in state["adapters"] if n in by_name
    )


def restore_state(state, setter=None):
    """依 ``original`` 精準還原，回傳 ``(new_state, result)``。

    setter 可注入以便測試 (簽名同 ``set_binding``)。只有實際有網卡處理成功
    才把 enabled/original 清掉；失敗時保留原始紀錄，讓下次啟動仍能還原。
    """
    new_state = normalize_state(state)
    names = plan_restore(new_state)
    if not names:
        return new_state, {"ok": True, "results": [], "changed": [], "noop": True}
    fn = setter or set_binding
    result = fn(names, True)
    applied = [r for r in result.get("results", []) if r.get("state") == "ok"]
    if result.get("ok") and applied:
        new_state["enabled"] = False
        new_state["original"] = {}
    return new_state, result
