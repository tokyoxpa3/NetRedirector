<#
.SYNOPSIS
    NetRedirector 統一建置腳本。自動偵測 MSVC Build Tools 編譯 C DLL，
    並可選執行 Nuitka 打包為獨立執行檔。

.DESCRIPTION
    取代 nuitka_packager.py GUI 的 CLI 建置方案。支援三種模式：
    - 預設：僅編譯 DLL (最快)
    - -Standalone：編譯 DLL + Nuitka 目錄模式
    - -Onefile：編譯 DLL + Nuitka 單一 exe 模式

.PARAMETER DllOnly
    僅編譯 DLL (預設行為)，不執行 Nuitka 打包。

.PARAMETER Standalone
    編譯 DLL 後以 Nuitka --standalone 模式打包 (產出目錄)。

.PARAMETER Onefile
    編譯 DLL 後以 Nuitka --onefile 模式打包 (產出單一 exe)。

.PARAMETER EntryPoint
    打包入口腳本，預設為 IntegratedApp.py。

.PARAMETER ConsoleMode
    打包時保留主控台視窗 (預設隱藏主控台)。

.PARAMETER NoDll
    跳過 DLL 編譯 (僅執行 Nuitka 打包，需已有編譯好的 DLL)。

.PARAMETER Force
    打包前若 IntegratedApp.exe 正在執行，強制結束程序並停止 WinDivert 服務
    （跳過優雅關閉，未儲存的設定變更會遺失）。預設不強制，會要求手動關閉。

.EXAMPLE
    .\build.ps1                        # 僅編譯 DLL
    .\build.ps1 -Standalone            # 編譯 DLL + 打包 standalone
    .\build.ps1 -Onefile -ConsoleMode  # 編譯 DLL + 打包單一 exe (含主控台)
    .\build.ps1 -Standalone -NoDll     # 僅打包 (跳過 DLL 編譯)
    .\build.ps1 -Standalone -Force     # 打包 (自動強制關閉執行中的應用程式)
#>

param(
    [switch]$DllOnly,
    [switch]$Standalone,
    [switch]$Onefile,
    [string]$EntryPoint = "IntegratedApp.py",
    [switch]$ConsoleMode,
    [switch]$NoDll,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ============================================================
# 步驟 1: 編譯 C DLL
# ============================================================
if (-not $NoDll) {
    Write-Host "=== 編譯 NetRedirector.dll ===" -ForegroundColor Cyan

    # 嘗試透過 vswhere 找到 MSVC 環境
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    }

    $vcvars = $null
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -property installationPath
        if ($vsPath) {
            # 嘗試多個可能的 vcvars64.bat 路徑
            $candidates = @(
                "$vsPath\VC\Auxiliary\Build\vcvars64.bat",
                "$vsPath\VC\Auxiliary\Build\vcvarsamd64.bat",
                "$vsPath\Common7\Tools\VsDevCmd.bat"
            )
            foreach ($c in $candidates) {
                if (Test-Path $c) { $vcvars = $c; break }
            }
        }
    }

    # 備用: 常見 VS 2022 Build Tools 路徑
    if (-not $vcvars) {
        $fallback = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $fallback) { $vcvars = $fallback }
    }

    if (-not $vcvars) {
        Write-Warning "找不到 MSVC Build Tools。請先安裝 Visual Studio Build Tools 2022 或從 Developer Command Prompt 執行此腳本。"
        Write-Warning "嘗試直接用 cl... (需已在 PATH 上)"
    } else {
        Write-Host "  找到 vcvars64.bat: $vcvars"
    }

    $dllDir = "NetRedirector"
    $dllSrc = @(
        "NetRedirector.c", "NR_Core.c", "NR_Protocol.c",
        "NR_RuleEngine.c", "NR_State.c", "NR_Utils.c"
    )
    $dllLibs = "windivert.lib User32.lib Advapi32.lib Ws2_32.lib Iphlpapi.lib"

    # 透過暫存 .bat 執行 vcvars64 + cl，避免 cmd 引號巢狀問題
    $batPath = Join-Path $env:TEMP "build_dll_$PID.bat"
    $batContent = "@echo off`r`n"
    if ($vcvars) {
        # [Fixed] 必須使用 CALL: 在 bat 內執行另一個 bat 若不加 CALL, 控制權不會返回,
        # cl 永遠不會執行, 導致 DLL 一直複製舊檔 (功能修復不會進到 DLL)
        $batContent += "CALL `"$vcvars`" >nul 2>&1`r`n"
    }
    $batContent += "cl /nologo /LD /DNETREDIRECTOR_EXPORTS $($dllSrc -join ' ') /Fe:NetRedirector.dll /I. $dllLibs"
    [System.IO.File]::WriteAllText($batPath, $batContent)

    Write-Host "  執行 cl: $($dllSrc -join ' ')" -ForegroundColor Gray
    # [Fixed] 改用 cmd /c 同步執行: Start-Process -Wait 在部分環境會在子程序
    # 結束後仍不返回 (編譯已完成但腳本永久卡住), cmd /c 由 PowerShell 直接
    # 等待、結束碼經 $LASTEXITCODE 取得, 行為穩定且輸出即時。
    Push-Location $dllDir
    try {
        & cmd.exe /c $batPath
        $dllExitCode = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    Remove-Item $batPath -Force -ErrorAction SilentlyContinue

    if ($dllExitCode -ne 0) {
        Write-Error "DLL 編譯失敗 (exit code: $dllExitCode)"
        exit 1
    }

    # 複製 DLL 到專案根目錄 (若被執行中的應用程式鎖定，提示後處理)
    try {
        Copy-Item "$dllDir\NetRedirector.dll" "NetRedirector.dll" -Force -ErrorAction Stop
        Write-Host "  DLL 編譯成功！已複製到 NetRedirector.dll" -ForegroundColor Green
    } catch {
        Write-Warning "  根目錄 NetRedirector.dll 被佔用，無法覆寫 (應用程式可能正在執行)。"
        if ($Standalone -or $Onefile) {
            # [Fixed] 打包模式下必須中止: 繼續會把「過期 DLL」打進發佈包,
            # 建置顯示成功但修復沒進包, 極難察覺
            Write-Error "已中止打包 (根目錄 DLL 無法更新)。請關閉 NetRedirector 應用程式後重新執行。"
            exit 1
        }
    }
}

# ============================================================
# 步驟 2: Nuitka 打包 (僅在指定 -Standalone 或 -Onefile 時)
# ============================================================
if (-not ($Standalone -or $Onefile)) {
    Write-Host "=== 完成 (DLL only) ===" -ForegroundColor Cyan
    exit 0
}

Write-Host "=== Nuitka 打包 ===" -ForegroundColor Cyan

# [Added] 殘留的 WinDivert 驅動服務會鎖住 .sys/.dll 檔 (核心載入中無法覆寫),
# 導致 Nuitka 複製執行期檔案時 PermissionError。應用程式沒在跑時自動停掉;
# 應用程式在跑時：預設中止並提示手動關閉，加 -Force 則自動強制結束再打包。
$wdSvc = Get-Service -Name "WinDivert" -ErrorAction SilentlyContinue
if ($wdSvc -and $wdSvc.Status -eq "Running") {
    $appProc = Get-Process -Name "IntegratedApp" -ErrorAction SilentlyContinue
    if ($appProc) {
        if (-not $Force) {
            Write-Error "NetRedirector 應用程式執行中 (IntegratedApp.exe), 驅動檔案被鎖定。請先關閉應用程式再打包（或加 -Force 自動強制關閉）。"
            exit 1
        }
        Write-Host "  -Force：強制結束 IntegratedApp.exe (跳過優雅關閉，未儲存的設定變更會遺失)..." -ForegroundColor Yellow
        $appProc | Stop-Process -Force
        Start-Sleep -Seconds 2
    }

    # 停止 WinDivert 驅動服務，釋放被鎖定的 .sys/.dll 檔
    Write-Host "  偵測到 WinDivert 驅動服務 (執行中), 嘗試停止..." -ForegroundColor Yellow
    & sc.exe stop WinDivert | Out-Null
    Start-Sleep -Seconds 2
    $wdSvc.Refresh()
    if ($wdSvc.Status -eq "Running") {
        Write-Error "無法停止 WinDivert 驅動服務, .sys 被鎖定無法打包。請以管理員執行: sc.exe stop WinDivert 後重試。"
        exit 1
    }
    Write-Host "  驅動服務已停止。" -ForegroundColor Gray
}

# 確認入口腳本存在
if (-not (Test-Path $EntryPoint)) {
    Write-Error "找不到入口腳本: $EntryPoint"
    exit 1
}

# [Fixed] 優先使用專案 .venv 的 Python: 打包相依 (Nuitka/PySide6) 只裝在 venv,
# 從未啟用 venv 的 PowerShell 直接執行時, PATH 上的系統 python 沒有 nuitka 會失敗
$pythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) { $pythonExe = "python" }
Write-Host "  使用 Python: $pythonExe" -ForegroundColor Gray

& $pythonExe -m nuitka --version >$null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "找不到 Nuitka。請先執行: $pythonExe -m pip install -r requirements-dev.txt"
    exit 1
}

# exe 圖示: 若 assets/app_icon.ico 不存在，先以 app_icon.py 產生
$iconPath = Join-Path $ScriptDir "assets\app_icon.ico"
if (-not (Test-Path $iconPath)) {
    Write-Host "  產生 exe 圖示..." -ForegroundColor Gray
    & $pythonExe (Join-Path $ScriptDir "app_icon.py")
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $iconPath)) {
        Write-Error "產生 exe 圖示失敗 (assets/app_icon.ico 不存在)"
        exit 1
    }
}

# 建構 Nuitka 命令
# [Fixed] 使用 splatting (& $pythonExe @nuitkaArgs): Windows PowerShell 5.1 的
# 「& $陣列變數」不會展開成指令+參數, 會把整個陣列當成單一指令名稱而失敗
# (PowerShell 7 才支援前者, 但不能假設使用者裝了 pwsh 7)。
$mode = if ($Onefile) { "--onefile" } else { "--standalone" }
$nuitkaArgs = @(
    "-m", "nuitka",
    "$mode",
    # [Fixed] CI/全新環境: standalone 需要 Dependency Walker, Nuitka 的互動式
    # 下載提示在非互動環境會自動答 "no" 而 FATAL; 此旗標讓它自動下載
    "--assume-yes-for-downloads",
    "--enable-plugin=pyside6",
    "--include-data-dir=locale=locale",
    "--windows-icon-from-ico=assets\app_icon.ico"
)

if (-not $ConsoleMode) {
    $nuitkaArgs += "--windows-console-mode=disable"
}

# 包含執行時期支援檔案 (DLL / 驅動)
# 注意: 不可打包 config.json — 那是使用者本機設定 (含個人代理與加密密碼),
#       打包進發佈 artifact 會外流開發者私人組態。應用程式缺檔時會以空白設定啟動。
$runtimeFiles = @("NetRedirector.dll", "WinDivert.dll", "WinDivert64.sys")
foreach ($f in $runtimeFiles) {
    if (Test-Path $f) {
        $nuitkaArgs += "--include-data-files=$f=$f"
    }
}

$nuitkaArgs += "--remove-output"
$nuitkaArgs += $EntryPoint

Write-Host "  執行: $pythonExe $($nuitkaArgs -join ' ')" -ForegroundColor Gray
Write-Host "" -ForegroundColor Gray

$global:lastExitCode = 0
& $pythonExe @nuitkaArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Nuitka 打包失敗 (exit code: $LASTEXITCODE)"
    exit 1
}

Write-Host ""
Write-Host "=== 建置完成！ ===" -ForegroundColor Green
if ($Onefile) {
    Write-Host "  exe 產出: ${EntryPoint}.onefile-dist\$([System.IO.Path]::GetFileNameWithoutExtension($EntryPoint)).exe" -ForegroundColor Yellow
    Write-Host "  注意: 單一 exe 首次啟動時會自行解壓，可能導致防毒軟體誤報。" -ForegroundColor Yellow
} else {
    Write-Host "  目錄: ${EntryPoint}.dist\" -ForegroundColor Yellow
    Write-Host "  注意: 執行前確認 WinDivert64.sys 與 WinDivert.dll 在同目錄。" -ForegroundColor Yellow
}