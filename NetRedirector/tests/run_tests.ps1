<#
.SYNOPSIS
    編譯並執行 C 核心單元測試 (NetRedirector/tests/test_*.c)。

.DESCRIPTION
    每個測試是獨立的 EXE，連結真實的 .c 原始碼 (含 vcvars64 + cl)。
    用法: .\run_tests.ps1 [-Name 名稱片段]
    範例: .\run_tests.ps1              # 跑全部 (預設 *)
          .\run_tests.ps1 -Name rules  # 只跑 test_rules.c
#>

param(
    [string]$Name = "*"
)

$ErrorActionPreference = "Stop"
$TestDir = Split-Path -Parent $MyInvocation.MyCommand.Path   # ...\NetRedirector\tests
$DllDir = Split-Path -Parent $TestDir                         # ...\NetRedirector
$RootDir = Split-Path -Parent $DllDir                         # 倉庫根目錄
Set-Location $RootDir

# 找出 vcvars64.bat
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe" }

$vcvars = $null
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath
    if ($vsPath) {
        foreach ($c in @("$vsPath\VC\Auxiliary\Build\vcvars64.bat", "$vsPath\VC\Auxiliary\Build\vcvarsamd64.bat")) {
            if (Test-Path $c) { $vcvars = $c; break }
        }
    }
}
if (-not $vcvars) {
    $fb = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $fb) { $vcvars = $fb }
}
if (-not $vcvars) { Write-Error "找不到 MSVC Build Tools (vcvars64.bat)" }

$dllSrc = @("NetRedirector.c", "NR_Core.c", "NR_Protocol.c", "NR_RuleEngine.c", "NR_State.c", "NR_Utils.c", "NR_PidMap.c")
$libs = "windivert.lib User32.lib Advapi32.lib Ws2_32.lib Iphlpapi.lib"

$testFiles = Get-ChildItem "$TestDir\test_$Name.c" -ErrorAction SilentlyContinue
if (-not $testFiles) { Write-Error "找不到測試: $TestDir\test_$Name.c" }

$failed = @()
foreach ($tf in $testFiles) {
    $base = $tf.BaseName
    $exe = Join-Path $tf.DirectoryName "$base.exe"
    $batPath = Join-Path $env:TEMP "run_test_$PID.bat"
    $batContent = "@echo off`r`n"
    $batContent += "CALL `"$vcvars`" >nul 2>&1`r`n"   # 必須 CALL, 否則 cl 不會執行
    $batContent += "cd /d `"$DllDir`"`r`n"
    # /utf-8: 原始檔為 UTF-8, 但 cl 預設依系統字碼頁 (此機器為 950) 解讀,
    # 註解中的中文只會產生 C4819 警告, 字串常值中的中文則會直接編譯失敗。
    $batContent += "cl /nologo /utf-8 /DNETREDIRECTOR_EXPORTS tests\$base.c $($dllSrc -join ' ') /Fe:tests\$base.exe /I. /Itests $libs"
    [System.IO.File]::WriteAllText($batPath, $batContent)

    Write-Host "`n=== 編譯 $base ===" -ForegroundColor Cyan
    # [Fixed] 改用 cmd /c 同步執行 (Start-Process -Wait 在部分環境會永久卡住);
    # bat 內已自行 cd /d 到 $DllDir, 結束碼經 $LASTEXITCODE 取得。
    & cmd.exe /c $batPath
    $compileExit = $LASTEXITCODE
    Remove-Item $batPath -Force -ErrorAction SilentlyContinue
    if ($compileExit -ne 0) {
        Write-Host "  [編譯失敗] $base" -ForegroundColor Red
        $failed += "$base (compile)"
        continue
    }

    Write-Host "=== 執行 $base ===" -ForegroundColor Cyan
    & $exe
    if ($LASTEXITCODE -ne 0) { $failed += "$base (run)" }

    # 清理產物 (.exe/.lib/.exp 產生在 tests\ 下, .obj 產生在 NetRedirector\ 下)
    Remove-Item "$TestDir\$base.exe", "$TestDir\$base.lib", "$TestDir\$base.exp", "$TestDir\$base.obj" -Force -ErrorAction SilentlyContinue
    Remove-Item "$DllDir\$base.exe", "$DllDir\$base.obj", "$DllDir\$base.lib", "$DllDir\$base.exp" -Force -ErrorAction SilentlyContinue
    Remove-Item "$DllDir\NetRedirector.obj", "$DllDir\NR_*.obj" -Force -ErrorAction SilentlyContinue
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host "=== 全部 C 測試通過 ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== 失敗: $($failed -join ', ') ===" -ForegroundColor Red
    exit 1
}
