# -*- coding: utf-8 -*-
"""自動更新邏輯 — 純網路／檔案處理，無 Qt 依賴 (方便單獨測試)。

流程：
1. check_update()     → 查 GitHub Release API，比對版本，回傳更新資訊或 None。
2. stage_update()     → 下載 zip + SHA256 清單 → 校驗 → 解壓到 <dist>.new。
3. apply_and_restart() → 寫入背景替換腳本並啟動，主程式隨後自行關閉。

安全要求：下載的更新檔必須通過 SHA-256 校驗才會解壓、替換，否則中止。
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

import requests

from version import UPDATE_API_URL

_TIMEOUT_CHECK = 15      # 檢查更新 (API) 逾時秒數
_TIMEOUT_DOWNLOAD = 180  # 下載更新檔逾時秒數


def parse_semver(tag):
    """把 git tag (可能帶 v 前綴) 轉成純版本字串。"""
    t = (tag or "").strip()
    if t.lower().startswith("v"):
        t = t[1:]
    return t


def _version_tuple(v):
    """把 "1.10.0" 轉成可比較的整數 tuple，避免字串比對 "1.10.0" < "1.9.0" 的錯誤。"""
    parts = []
    for p in str(v).split("."):
        digits = "".join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _is_newer(latest, current):
    return _version_tuple(latest) > _version_tuple(current)


def get_latest_release(timeout=_TIMEOUT_CHECK):
    """呼叫 GitHub Releases API 取得最新 release JSON。"""
    r = requests.get(
        UPDATE_API_URL,
        timeout=timeout,
        headers={"Accept": "application/vnd.github+json"},
    )
    r.raise_for_status()
    return r.json()


def check_update(current_version, timeout=_TIMEOUT_CHECK):
    """比對最新 release 與目前版本。

    回傳 None 表示已是最新；有新版本時回傳 dict:
        {"version", "asset_name", "url", "checksum_url", "notes", "size"}
    網路錯誤 / 資產缺失時拋出例外，由呼叫端處理。
    """
    release = get_latest_release(timeout)
    latest = parse_semver(release.get("tag_name", ""))
    if not latest or not _is_newer(latest, current_version):
        return None

    assets = release.get("assets", [])
    zip_asset = next(
        (a for a in assets if a.get("name", "").lower().endswith(".zip")), None)
    checksum_asset = next(
        (a for a in assets
         if a.get("name", "").lower() in ("sha256sums.txt", "sha256.txt", "checksums.txt")),
        None)

    if not zip_asset or not checksum_asset:
        raise RuntimeError("release 缺少 zip 或 SHA256 資產，無法安全更新")

    return {
        "version": latest,
        "asset_name": zip_asset["name"],
        "url": zip_asset["browser_download_url"],
        "checksum_url": checksum_asset["browser_download_url"],
        "notes": release.get("body") or "",
        "size": zip_asset.get("size", 0),
    }


def verify_sha256(path, expected_hex):
    """計算檔案 SHA-256 並與期望值 (十六進位字串) 比對。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower() == str(expected_hex).strip().lower()


def _parse_expected_sha256(checksum_text, asset_name):
    """從 SHA256SUMS 內文找出指定資產的雜湊值 (格式: "<hash>  <name>")。"""
    for line in checksum_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and asset_name in line:
            return parts[0].strip()
    return None


def is_frozen():
    """Nuitka 打包後 sys.frozen 為 True；開發模式 (跑 .py) 為 False。"""
    return bool(getattr(sys, "frozen", False))


def current_dist_dir():
    """目前執行檔所在資料夾 (打包後即 .dist 目錄)。"""
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def stage_update(asset_url, asset_name, checksum_url, timeout=_TIMEOUT_DOWNLOAD):
    """下載並驗證更新，解壓到 <dist>.new，回傳新目錄路徑。

    任何一步失敗都拋例外；下載的暫存檔會在 finally 中清理。
    """
    # 1. 先取 SHA256 清單 (小檔)，解析出本資產的期望雜湊
    r = requests.get(checksum_url, timeout=timeout)
    r.raise_for_status()
    expected = _parse_expected_sha256(r.text, asset_name)
    if not expected:
        raise RuntimeError("SHA256 清單中找不到對應資產的雜湊值，中止更新")

    # 2. 下載 zip 到暫存檔
    fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="netredir_update_")
    os.close(fd)
    try:
        r = requests.get(asset_url, timeout=timeout, stream=True)
        r.raise_for_status()
        with open(tmp_path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)

        # 3. 校驗 (不符即中止，避免執行被竄改的二進位檔)
        if not verify_sha256(tmp_path, expected):
            raise RuntimeError("下載的更新檔 SHA256 校驗失敗，已中止更新")

        # 4. 解壓到 <dist>.new
        dist_dir = current_dist_dir()
        new_dir = dist_dir + ".new"
        if os.path.exists(new_dir):
            shutil.rmtree(new_dir, ignore_errors=True)
        os.makedirs(new_dir, exist_ok=True)

        with zipfile.ZipFile(tmp_path) as z:
            # 防 zip-slip：解壓前先確認所有目標路徑仍在 new_dir 內
            new_base = os.path.normpath(new_dir) + os.sep
            for m in z.infolist():
                target = os.path.normpath(os.path.join(new_dir, m.filename))
                if not target.startswith(new_base):
                    raise RuntimeError("更新檔包含不安全的解壓路徑，已中止更新")
            z.extractall(new_dir)

        return new_dir
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def _apply_script_content():
    """回傳背景替換腳本 (PowerShell) 內容；路徑以參數傳入，避免引號／編碼問題。"""
    return r'''param(
    [string]$Dist,
    [string]$NewDir,
    [string]$OldDir,
    [string]$Exe,
    [string]$ExeName
)
$ErrorActionPreference = 'SilentlyContinue'

# 1. 等主程式完全退出 (程式檔名不含 .exe)
while (Get-Process -Name $ExeName -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 1
}

# 2. 清理上次更新殘留的舊版本資料夾
if (Test-Path $OldDir) { Remove-Item $OldDir -Recurse -Force }

# 3. 原子交換：dist → old、new → dist (重試以等待檔案解鎖)
$ok = $false
for ($i = 0; $i -lt 15 -and -not $ok; $i++) {
    if ((Test-Path $Dist) -and (Test-Path $NewDir)) {
        Rename-Item $Dist $OldDir -Force -ErrorAction SilentlyContinue
    }
    if ((Test-Path $NewDir) -and -not (Test-Path $Dist)) {
        Rename-Item $NewDir $Dist -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $Exe) { $ok = $true } else { Start-Sleep -Seconds 1 }
}

# 4. 重新啟動
if ($ok) {
    Start-Process -FilePath $Exe -WorkingDirectory (Split-Path $Exe)
}

# 5. 背景清除舊版本 (不阻塞新程式啟動)
if (Test-Path $OldDir) {
    Start-Job -ScriptBlock { param($p) Remove-Item $p -Recurse -Force } -ArgumentList $OldDir | Out-Null
}
'''


def apply_and_restart():
    """寫入並啟動背景替換腳本；呼叫端須隨後優雅關閉主程式。

    僅在打包後的可執行檔中允許 (開發模式直接丟例外，避免誤動 repo 目錄)。
    """
    if not is_frozen():
        raise RuntimeError("自動更新僅支援打包後的可執行檔")

    dist_dir = current_dist_dir()
    exe_path = sys.executable
    exe_base = os.path.basename(exe_path)          # 例如 IntegratedApp.exe
    exe_name = os.path.splitext(exe_base)[0]       # Get-Process 需去掉 .exe
    new_dir = dist_dir + ".new"
    old_dir = dist_dir + ".old"
    install_dir = os.path.dirname(dist_dir)

    script_path = os.path.join(install_dir, "apply_update.ps1")
    with open(script_path, "w", encoding="utf-8") as f:
        f.write(_apply_script_content())

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", script_path,
         "-Dist", dist_dir, "-NewDir", new_dir, "-OldDir", old_dir,
         "-Exe", exe_path, "-ExeName", exe_name],
        cwd=install_dir,
        creationflags=creationflags,
    )
