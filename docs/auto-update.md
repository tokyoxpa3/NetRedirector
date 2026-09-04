# 自動更新機制實作指南（含踩坑紀錄）

> 適用於 **Windows + Python + Nuitka/PyInstaller 打包**的桌面應用程式。
> 本文件整理自 NetRedirector 專案實作自動更新的完整歷程，包含所有踩過的坑與最終解法。
> 其他專案若要實作類似機制，直接照這份來，就不用再重走一遍冤枉路。

---

## 一、整體架構

```
[發佈端]
  手動遞增版本號 → 打 git tag（例 v1.7.0）→ push
    ↓ CI 自動
  改寫 version.py 的版本號 → 打包 zip → 產生 SHA256SUMS.txt → 建立 GitHub Release
        ↓
[用戶端 App]
  「檢查更新」→ 查 GitHub Release API → 比對版本
    → 有新版本 → 下載 zip → SHA-256 校驗 → 解壓到旁路目錄
    → 啟動背景替換腳本（等主程式退出 → 交換資料夾 → 保留設定檔 → 重啟）
```

核心設計原則：

1. **版本號單一來源**（`version.py`，CI 用 tag 覆寫）。
2. **下載的二進位檔強制 SHA-256 校驗**，否則不套用（防供應鏈攻擊）。
3. **原子替換**：先下載到旁路目錄，交換失敗可回滾，不留半套狀態。
4. **執行期資料必須跨版本保留**（設定檔、歷史記錄等）。
5. **凍結偵測與 exe 路徑必須針對打包器各自處理**（見第五節，這是踩坑重災區）。

---

## 二、版本管理：單一來源

建立 `version.py`：

```python
APP_VERSION = "1.6.4"                 # 唯一版本來源，發佈前手動遞增
GITHUB_REPO = "yourname/yourproject"  # release API 用
UPDATE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
```

發佈流程（固定不變）：

1. 手動把 `version.py` 的 `APP_VERSION` 遞增。
2. 打跟它一致的 git tag（`v1.6.5`）。
3. push，CI 自動把 tag 版本寫回 `version.py` 再編譯進 exe（避免手動改兩處）。

---

## 三、發佈端（CI）

用 tag 觸發獨立 workflow（`.github/workflows/release.yml`）：

```yaml
on:
  push:
    tags: ['v*']

permissions:
  contents: write
```

關鍵步驟：

1. **把 tag 版本注入 `version.py`**（Nuitka 會把這值編譯進 exe）：
   ```powershell
   $v = $env:GITHUB_REF_NAME -replace '^v',''
   $raw = (Get-Content version.py -Raw) -replace 'APP_VERSION\s*=\s*"[^"]*"',
            ('APP_VERSION = "' + $v + '"')
   Set-Content version.py -Value $raw -NoNewline -Encoding utf8
   ```
   這一步很重要：因為 `version.py` 是常數字面量，Nuitka 編譯時會把它「凍」進二進位檔；若用 `os.environ` 讀版本，使用者端執行時不會有那個環境變數，版本會跑掉。

2. **打包 zip**：把 standalone 產出的 `.dist` 資料夾**內容**（不帶外層資料夾）壓成 `App-vX.Y.Z-win64.zip`。

3. **產生 SHA256SUMS.txt**：
   ```powershell
   $hash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
   "$hash  $zip" | Set-Content SHA256SUMS.txt -Encoding ascii
   ```

4. **建立 Release**：`gh release create $TAG $zip SHA256SUMS.txt --generate-notes`。

---

## 四、用戶端流程

### 4.1 檢查更新

```python
def check_update(current_version):
    release = requests.get(UPDATE_API_URL, timeout=15).json()
    latest = release["tag_name"].lstrip("v")
    if not _is_newer(latest, current_version):
        return None                      # 已是最新
    zip_asset = find_asset(release, ".zip")
    checksum_asset = find_asset(release, "sha256sums.txt")
    return { "version": latest, "url": ..., "checksum_url": ..., ... }
```

> 版本比較要用**整數 tuple**，不要用字串比對：字串比對會誤判 `1.10.0 < 1.9.0`。

### 4.2 下載 + 校驗 + 解壓

```python
def stage_update(url, name, checksum_url):
    expected = parse_sha256(checksum_url, name)   # 從 SHA256SUMS 解析出本資產的雜湊
    tmp = download(url)
    if not verify_sha256(tmp, expected):
        raise RuntimeError("SHA256 校驗失敗，中止")
    extract(tmp, dist_dir + ".new")               # 解壓到旁路目錄
    # 解壓前做 zip-slip 防護：確認每個條目的目標路徑都在 new_dir 內
```

### 4.3 原子替換 + 重啟

由背景 PowerShell 腳本執行（主程式此時已自行關閉）：

1. 等主程式程序真的退出（`Get-Process -Name <exe名>`）。
2. 交換：`dist` → `dist.old`、`dist.new` → `dist`（帶重試，處理檔案解鎖延遲）。
3. **把執行期資料從 `dist.old` 搬回 `dist`**（`config.json`、歷史檔等）——不做這步設定就會被清零。
4. `Start-Process -UseShellExecute $false` 重啟。
5. 清理 `dist.old`（同步重試）。

---

## 五、踩坑紀錄（最重要的一節）

### 坑 1：Nuitka 不設 `sys.frozen`

- **現象**：打包後程式仍被誤判成「原始碼模式」，自動更新的套用步驟被擋。
- **根因**：`sys.frozen` 是 PyInstaller / cx_Freeze 的慣例；**Nuitka 是注入模組全域變數 `__compiled__ = True`**，不設 `sys.frozen`。
- **解法**：凍結偵測要同時涵蓋三種打包器：

```python
def is_frozen():
    if getattr(sys, "frozen", False):          # PyInstaller / cx_Freeze
        return True
    if hasattr(sys, "_MEIPASS"):               # PyInstaller onefile
        return True
    if globals().get("__compiled__", False):   # Nuitka
        return True
    return False
```

> 注意 `globals()` 在函式內指的是「定義該函式的模組」的 dict，所以 `globals().get("__compiled__")` 要寫在被 Nuitka 編譯的那個模組裡才有效。

### 坑 2：Nuitka 的 `sys.executable` 指向內建 `python.exe`（本專案最痛的一坑）

- **現象**：更新後「只關閉、不重啟」。查 log 發現 `Exe=[...\python.exe] ExeName=[python]`、`swap ok=False`。
- **根因**：Nuitka standalone 會把 `sys.executable` 設成 **dist 內建的 `python.exe`**，而不是真正的 `IntegratedApp.exe`。於是 exe 名稱被算成「python」，替換腳本去等「python」程序退出——但真正在跑的是 `IntegratedApp`，等錯對象 → 太早去交換資料夾 → 資料夾被執行中的程式鎖住 → 交換失敗 → 跳過重啟。
- **解法**：**用 `sys.argv[0]` 取得真正的 exe**，失敗才回退 `sys.executable`：

```python
def _frozen_exe_path():
    argv0 = sys.argv[0] if sys.argv else ""
    p = os.path.abspath(argv0) if argv0 else ""
    if p and p.lower().endswith(".exe"):
        return p
    return os.path.abspath(sys.executable)
```

`current_dist_dir()` 與 exe 名稱（`Get-Process` 用的）都要從這個 helper 來，**不要直接信任 `sys.executable`**。

### 坑 3：PowerShell `Start-Process` 預設走 ShellExecute 會卡住

- **現象**：背景替換腳本卡在重啟那一步，超過 2 分鐘無回應（沙盒實測）。
- **根因**：Windows PowerShell 5.1 的 `Start-Process` 預設用 **ShellExecute** 啟動；遇到無效 exe 或特定 manifest 的程式，ShellExecute 會彈對話框或直接卡住。
- **解法**：加 `-UseShellExecute $false`（改走 CreateProcess，直接繼承權限、行為可預期）：

```powershell
Start-Process -FilePath $Exe -WorkingDirectory $Dist -UseShellExecute $false -ErrorAction Stop
```

### 坑 4：PowerShell 5.1 讀無 BOM 的 UTF-8 會亂碼

- **現象**：腳本內的中文註解亂碼，甚至影響解析。
- **根因**：無 BOM 的 `.ps1` 會被 PS 5.1 用系統 ANSI 字碼頁讀取，UTF-8 中文變成亂碼。
- **解法**：二選一——
  1. 產生 `.ps1` 時用 `open(path, "w", encoding="utf-8-sig")`（加 BOM）；
  2. 更保險：**腳本內容保持全 ASCII**（註解用英文），從源頭排除編碼問題。

### 坑 5：日誌路徑別依賴 `$env:TEMP`，也別放在 try 外面

- **現象**：重啟失敗，但想看的日誌完全沒寫出來，無從偵錯。
- **根因**：`$logPath = Join-Path $env:TEMP ...` 寫在 `try/catch` **外面**；一旦 `$env:TEMP` 異常或 Join-Path 拋錯，腳本直接終止、不留任何痕跡。
- **解法**：
  1. 日誌路徑由 **Python 端當參數傳入**（明確、可預期），不要讓腳本自己拼 `$env:TEMP`。
  2. 逐步記錄（start / app exited / swap / config / restart / cleanup），每步都寫。
  3. 把 powershell 的 stderr 另外導到檔案，捕捉解析/執行錯誤。

### 坑 6：`Start-Job` 會卡住 stdout/stderr 管道

- **現象**：用 `subprocess.run(capture_output=True)` 跑替換腳本時永遠不返回。
- **根因**：`Start-Job` 會 spawn 一個孫程序 powershell，它**繼承了 stdout/stderr 管道**，父程序等不到 EOF。
- **解法**：背景清理別用 `Start-Job`，改成**同步重試**：

```powershell
for ($i = 0; $i -lt 10 -and -not $cleaned; $i++) {
    Remove-Item $OldDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $OldDir)) { $cleaned = $true } else { Start-Sleep -Seconds 1 }
}
```

### 坑 7：資料夾交換會把設定檔一起刪掉

- **現象**：更新成功但使用者設定全部歸零。
- **根因**：程式把 `config.json` 寫在執行檔同目錄（`.dist` 內），而「原子替換」是整個資料夾改名交換，所以設定檔跟著舊資料夾一起被丟。
- **解法**：交換完成後，把「執行期資料清單」從舊資料夾複製回新資料夾（在重啟之前）：

```powershell
foreach ($f in @('config.json','vpn_history.json')) {
    $src = Join-Path $OldDir $f
    if ((Test-Path $src) -and (Test-Path $Dist)) {
        Copy-Item $src (Join-Path $Dist $f) -Force -ErrorAction SilentlyContinue
    }
}
```

> 更根本的長遠解法：把使用者資料改存到 `%APPDATA%`，徹底脫離安裝目錄。這裡為了不破壞既有使用者設定位置，先用「搬回」應急。

### 坑 8：重啟要等「正確的程序名」退出

- **現象**：與坑 2 連動——等錯程序名，導致交換時檔案還被鎖。
- **解法**：`Get-Process -Name` 用的名字必須來自 `_frozen_exe_path()` 的 basename（去掉 `.exe`），不能來自 `sys.executable`。

### 坑 9：測試時的低版本/高版本「雞生蛋」問題

- **現象**：想測「更新」卻永遠顯示「已是最新版本」。
- **根因**：自動更新是「執行中的程式（舊）去下載並套用新程式」。所以：
  1. 執行中的那個版本**必須低於**最新 release；
  2. 執行中的那個版本**必須已經包含更新程式碼**（才有能力去下載+套用）。
- **解法**：測試時用「含修正的低版本 commit」當起點，再發一版更高的 release 當目標。
  例如：`git checkout <含修正的 commit>`（version 還是舊的）→ build → 跑起來 → 它會抓到最新的更高版本去更新。

### 坑 10：`git checkout <commit>` 測試會讓工作區變 detached HEAD

- **現象**：測試途中提交的 commit 落在「分離 HEAD」，push 時 `Everything up-to-date`，修正根本沒上 main。
- **解法**：
  1. 養成習慣：`git checkout main` 再 `git cherry-pick <修正 commit>`，把修正搬回 main。
  2. 提交前先 `git branch --show-current` 確認不在 detached HEAD。
  3. 提交後 `git log --oneline main -N` 驗證歷史完整。

---

## 六、安全注意事項

1. **SHA-256 校驗是底線**：下載的二進位檔必須通過校驗才解壓/套用，否則等於把供應鏈攻擊接進一個有系統層權限的工具。
2. **zip-slip 防護**：解壓前逐一檢查條目路徑是否仍在目標目錄內。
3. **不要打包 `config.json`**：使用者本機設定（含加密密碼）不能進 release 包，否則外流。
4. **程式碼簽章**：未簽章的 Nuitka/PyInstaller exe + 驅動安裝，很容易被 SmartScreen / 防毒誤報。正式對外釋出建議加 Authenticode 簽章（這是唯一無法自動化、需要你自有憑證的部分）。

---

## 七、一頁速查：發佈一版的標準動作

1. `version.py` 遞增 `APP_VERSION` → commit。
2. `git tag vX.Y.Z && git push --tags`（同時 push main）。
3. 等 CI 建完 GitHub Release（會自動產出 zip + SHA256SUMS.txt）。
4. 用「含更新程式碼的低版本」build 一個測試起點，跑「檢查更新」驗證下載→校驗→重啟→設定保留。

---

## 附錄：關鍵檔案對照

| 檔案 | 角色 |
|------|------|
| `version.py` | 版本號單一來源 |
| `updater.py` | 檢查/下載/校驗/解壓/替換腳本產生（純邏輯，無 GUI） |
| `_frozen_exe_path()` | 取得真正的 exe 路徑（繞過 Nuitka 的 `sys.executable` 陷阱） |
| `is_frozen()` | 三種打包器的凍結偵測 |
| `.github/workflows/release.yml` | tag 觸發自動打包 + 發 Release |
| 背景 `apply_update.ps1` | 等退出 → 交換 → 保留設定 → 重啟 → 清理 |
