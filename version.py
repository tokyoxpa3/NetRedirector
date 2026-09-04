# -*- coding: utf-8 -*-
"""應用程式版本 — 自動更新的唯一版本來源。

CI 建立 release 時，會把下方的 APP_VERSION 改寫成對應的 git tag 版本
(例如 tag v1.7.0 → APP_VERSION = "1.7.0")，Nuitka 再將其編譯進二進位檔，
使產出的可執行檔內建正確版本號。

本機開發／日常提交請在此手動遞增版本，並於發佈時打上一致的 git tag。
"""

APP_VERSION = "1.6.6"

# GitHub 更新來源 (release API)
GITHUB_REPO = "tokyoxpa3/NetRedirector"
UPDATE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

__all__ = ["APP_VERSION", "GITHUB_REPO", "UPDATE_API_URL"]
