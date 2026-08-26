# NetRedirector 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build](https://github.com/tokyoxpa3/NetRedirector/actions/workflows/build.yml/badge.svg)](https://github.com/tokyoxpa3/NetRedirector/actions/workflows/build.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform: Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey.svg)](https://www.microsoft.com/)
[![GUI: PySide6](https://img.shields.io/badge/GUI-PySide6-green.svg)](https://doc.qt.io/qtforpython/)
[![Core: WinDivert](https://img.shields.io/badge/Core-WinDivert-orange.svg)](https://www.reqrypt.org/windivert.html)

**NetRedirector** 是一個功能強大且專為進階玩家與開發者設計的Windows網路流量轉發與代理工具。它結合了高效能的本地端口路由（Hub）與系統級封包攔截（WinDivert 驅動層），支援 IPv4 / IPv6 雙棧、多網卡故障轉移、負載平衡及智慧局域網自動直連，並透過現代化的 PySide6 圖形介面提供極佳的操作體驗。

> 📖 **完整圖文操作教學**：[NetRedirector 使用教學（結合手機 5G Proxy Pro）](TUTORIAL.md) — 含實機截圖、逐步設定流程與常見問題。

---

## 📸 介面預覽 (UI Gallery)

> 💡 *提示：您可以將實際操作截圖放置於專案的 `docs/images/` 目錄下，並於下方表格中引用（目前使用 `1.png`、`2-1.png`、`2-2.png`、`3-1.png`、`3-2.png`、`4.png`；VPN Gate 分頁可新增 `5.png` 引用）。*

| 1. 端口路由管理 (Hub) | 2. 進程攔截規則 (Rules) |
| :---: | :---: |
| ![Hub 界面預覽](docs/images/1.png) | ![Rules 界面預覽](docs/images/2-1.png)<br>![Rules 界面預覽 2](docs/images/2-2.png) |
| *多本地監聽端口、網卡多對一綁定與即時延遲偵測* | *支援進程名稱/PID、多條件過濾與代理綁定* |

| 3. 自訂代理管理 (Proxies) | 4. 即時流量監控 (Monitor) |
| :---: | :---: |
| ![Proxies 界面預覽](docs/images/3-1.png)<br>![Proxies 界面預覽 2](docs/images/3-2.png) | ![Monitor 界面預覽](docs/images/4.png) |
| *SOCKS5 / HTTP 代理設定與一鍵可用性 Ping 測試* | *即時封包記錄、進程資訊與右鍵快速建立規則* |

---

## ✨ 功能特色

### 1. 端口路由管理 (Hub)
- **多端口監聽**：支援同時開啟多個本地監聽端口，滿足不同應用或遊戲的代理需求。
- **網卡多對一/多對多綁定**：可將特定本地端口綁定到指定的網路介面（Wi-Fi、乙太網路、VPN等）。
- **自動故障轉移與智慧選路**：自動選擇延遲最低的網路介面連線；當主介面失效時自動切換至備用介面。
- **快速搜尋與全選**：內建介面名稱篩選框與「全選顯示項目」快捷按鈕，海量網卡輕鬆管理。

### 2. 進程攔截規則 (Rules)
- **精準進程匹配**：支援按進程名稱（如 `chrome.exe`、`game.exe`）或特定 PID 設定規則。
- **多維度過濾條件**：可指定目標主機（Hosts）、目標端口（Ports）以及協議類型（TCP / UDP / ALL）。Hosts 欄位同時支援 **域名**（如 `*.google.com`、`google.com`）與 **IP**（如 `192.168.1.1`）：域名規則由核心定期重新解析為 IP 後再比對（快取 TTL 1 分鐘），DNS 變更最遲一分鐘內生效；多個目標可用 `;` 分隔。
- **三大規則動作**：支援 **代理 (Proxy)**、**直連 (Direct)** 與 **阻擋 (Block)**。
- **雙擊編輯與管理**：支援規則即時編輯修改、啟用/停用與刪除。

### 3. 自訂代理管理 (Proxies)
- **多協議支援**：完整支援 **SOCKS5** 與 **HTTP** 代理伺服器。
- **安全認證**：支援帳號密碼（Username / Password）身份驗證。
- **代理群組Ping測試**：一鍵測試所有代理伺服器的連線延遲與可用性。

### 4. 智慧局域網自動直連 (Local Subnet Direct)
- **私有網段自動直連**：目的地為私有網段（IPv4 `10/8`、`172.16/12`、`192.168/16`，IPv6 ULA `fc00::/7`）時自動繞過代理，確保區網內檔案傳輸、印表機、區域網路遊戲速度不受影響。
- **On-link 動態辨識**：自動識別本機任一張作用中網卡同網段（on-link）目標（含 ISP 派發的全球 IPv6 位址），維持最佳本機連線效能。

### 5. IPv6 雙棧支援
- **核心層完整支援**：WinDivert 攔截層完整支援 IPv4 / IPv6 雙棧封包。
- **SOCKS5 IPv6 轉發**：支援 SOCKS5 ATYP_IPV6 及 HTTP CONNECT `[IPv6]:port` 格式。
- **萬用字元比對**：IPv6 規則比對支援完整位址或 `*` 萬用匹配。

### 6. 高效網路診斷與流量監控
- 內建優化的 `network_utils` 模組，取代傳統緩慢的 cmd `ping` / `ipconfig` 命令，提供毫秒級網路介面檢測與即時延遲監控。
- 支援右鍵點擊即時流量記錄，一鍵快速新增進程攔截規則。

### 7. VPN Gate 節點自動派發 (VPN Gate 分頁)
- 抓取 [VPN Gate](https://www.vpngate.net/) 即時公開中繼節點清單，依速度/評分排序。
- 支援篩選：排除 `public-*` 節點、排除 port 443、最低速度門檻、指定國家。
- 對 SoftEther 虛擬網卡（`vpncmd.exe`）一鍵自動設定、連線並驗證 tunnel 通網；單一節點失敗自動換下一個候選。

---

## 🛠️ 系統需求

- **作業系統**：Windows 10 / 11 (x64)
- **運行權限**：**管理員權限 (Administrator)**（WinDivert 驅動程式攔截網路封包必須）
- **執行環境**：Python 3.10+ (推薦 Python 3.11)
- **VPN Gate 分頁 (選用)**：需安裝 [SoftEther VPN Client](https://www.vpngate.net/cn/download.aspx)（`vpncmd.exe`，簡體中文版 v4.44）。

---

## 📦 安裝步驟

1. **取得專案程式碼**
   ```bash
   git clone https://github.com/tokyoxpa3/NetRedirector.git
   cd NetRedirector
   ```

2. **建立並啟動虛擬環境 (建議)**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **安裝相依套件**
   ```bash
   pip install -r requirements.txt
   ```

4. **以管理員身份執行應用程式**
   - 右鍵點擊命令提示字元 (CMD) 或 PowerShell，選擇 **「以系統管理員身分執行」**。
   - 執行整合版主程式：
     ```bash
     python IntegratedApp.py
     ```

---

## 📖 詳細使用說明

### 一、 端口路由管理 (Hub 分頁)
1. **新增監聽端口**：於左側輸入框填入本地監聽端口（例如 `1080` 或 `8888`），點擊「新增端口」。
2. **選擇並綁定介面**：點擊左側列表中的端口，右側將列出所有可用網路介面。
3. **網卡篩選與勾選**：
   - 可在上方「過濾介面」輸入關鍵字快速搜尋（例如 `Wi-Fi`）。
   - 點擊「全選顯示項目」可快速選取當前篩選出的所有網卡。
4. **啟動路由服務**：勾選所需介面後，點擊「啟動/重啟選中端口」，即完成本地代理服務綁定。

### 二、 進程攔截規則 (Rules 分頁)
1. **選擇匹配方式**：勾選「進程名稱」或「PID」。
2. **填寫目標資訊**：
   - 範例（進程名稱）：`chrome.exe` 或 `steam.exe`
   - 範例（PID）：`1234`
3. **設定進階條件**：可選填目標主機（如 `*.google.com`）、端口（如 `443`）及傳輸協議（TCP/UDP/ALL）。Hosts 欄位支援 **域名**（如 `google.com`、`*.google.com`，`*.` 代表萬用子網域）與 **IP 位址**（如 `192.168.1.1`），多個目標以 `;` 分隔；域名規則會由核心**定期重新解析**（快取 TTL 1 分鐘）後與封包目標 IP 比對。
4. **選擇動作與代理**：
   - **代理**：指定透過某個已設定的自訂代理轉發。
   - **直連**：強制不經過代理，直接連線。
   - **阻擋**：攔截並阻斷該流量。
5. **管理規則**：點擊「新增規則」；若需修改，直接 **雙擊** 表格中的規則項目即可載入表單進行編輯。

### 三、 自訂代理管理 (Proxies 分頁)
1. **填寫代理參數**：
   - **名稱**：自訂辨識名稱（例如 `US-Node-1`）
   - **類型**：選擇 `SOCKS5` 或 `HTTP`
   - **IP Host / Port**：填入代理伺服器位址與端口。
   - **認證**：若代理需要密碼，填入 User 與 Pass。
2. **新增與測試**：點擊「新增代理」儲存。隨時可點擊「測試所有代理連線 (Ping)」檢驗代理節點的延遲與可用狀態。

### 四、 即時流量監控 (Monitor 分頁)
1. 查看即時產生的網路流量記錄（包含時間、進程名稱、PID、來源/目標 IP 與端口）。
2. 支援 **滑鼠右鍵點擊** 任意流量記錄行，彈出快捷選單，一鍵將該進程或目標加入攔截規則中。

### 五、 VPN Gate 節點派發 (VPN Gate 分頁)

> **前置需求**：需安裝 [SoftEther VPN Client](https://www.vpngate.net/cn/download.aspx)（`vpncmd.exe`，簡體中文版 v4.44），並已透過 VPN Client Manager 建立至少一張虛擬網卡。

1. **重新整理網卡**：點擊「重新整理網卡」列出所有 SoftEther 虛擬網卡，狀態欄以綠/紅顯示上線/離線。
2. **抓取節點**：點擊「抓取節點」從 [VPN Gate](https://www.vpngate.net/) 即時清單（`http://www.vpngate.net/api/iphone/`）取得公開中繼節點；Port 欄位從 OpenVPN 設定 base64 解碼後的 `remote` 行取出（SoftEther 與 OpenVPN 共用同一 listener）。
3. **設定篩選條件**：預設排除 `public-*` 節點與 port 443；可調整最低速度門檻（Mbps）及多選指定國家（留空=全部）。
4. **套用篩選**：依條件過濾，以 `(-score, ping)` 排序候選節點。
5. **一鍵上線**：自動對所有**離線**網卡依序指派候選節點：`AccountSet`（或 `AccountCreate`）→ 匿名認證（HUB=`VPNGATE`，使用者名稱=`vpn`）→ `AccountConnect` → 輪詢 `AccountStatusGet` 等待會話建立 → 取得網卡 IPv4 → 綁定該 IP 連 `1.1.1.1:443` 驗證 tunnel 通網；單一節點失敗自動斷線換下一個候選，本輪已用 IP 不會重複嘗試。

> **注意事項**
> - 抓取、連線等慢速操作皆在背景執行緒執行，請留意系統日誌進度。
> - VPN Gate 節點為公開免費中繼，速度與穩定性不保證；連線失敗屬正常流程，工具會自動嘗試下一個節點。
> - `vpncmd` 命令參數**不可用引號包裹**，否則會報「命令未找到」；`softether.py` 已正確處理此行為。
> - 錯誤碼 `rc=37`（指定設定未連接）是 `AccountStatusGet` 對離線帳號的正常回傳，`is_connected()` 會正確回傳 `False`，不會影響流程。

---

## 🗂️ 專案檔案結構

```
NetRedirector/
├── IntegratedApp.py         # 整合版主應用程式 (PySide6 GUI)
├── proxy_core.py            # 本地 SOCKS5 / 端口路由代理核心
├── network_utils.py         # 高效網路介面掃描與 Ping 診斷模組
├── NetRedirector.py         # WinDivert C 核心 Python 封裝器
├── tabs_vpngate.py          # VPN Gate 節點派發分頁 (PySide6)
├── vpngate.py               # VPN Gate 即時節點清單抓取/解析/排序
├── softether.py             # SoftEther vpncmd.exe 封裝 (連線/斷線/狀態)
├── vpngate_config.py        # VPN Gate 相關常數 (vpncmd 路徑、HUB、timeout)
├── requirements.txt         # Python 相依套件清單
├── NetRedirector.dll        # 核心 C 語言 DLL (封包攔截與轉發)
├── WinDivert.dll            # WinDivert 動態連結庫
├── WinDivert64.sys          # WinDivert 核心驅動程式
├── vcruntime140.dll         # Visual C++ 執行時期庫
├── docs/
│   └── images/              # UI 截圖目錄
│       ├── 1.png            # Hub 分頁截圖
│       ├── 2-1.png          # Rules 分頁截圖
│       ├── 2-2.png          # Rules 分頁截圖
│       ├── 3-1.png          # Proxies 分頁截圖
│       ├── 3-2.png          # Proxies 分頁截圖
│       └── 4.png            # Monitor 分頁截圖
└── NetRedirector/           # C 語言底層原始碼與編譯腳本
    ├── NetRedirector.c      # DLL 導出 API 與生命週期管理
    ├── NR_Core.c            # WinDivert 封包過濾與 UDP Relay
    ├── NR_Protocol.c        # SOCKS5 / HTTP 協議解析
    ├── NR_RuleEngine.c      # 規則比對引擎
    ├── NR_State.c           # 連線狀態追蹤
    ├── NR_Utils.c           # 工具函式 (EXE 解析、LAN/on-link 偵測、比對邏輯)
    └── build_dll.bat        # 相容入口 (指向 build.ps1)
```

---

## ⚙️ 建置 (Build)

### 方式 1: 統一建置腳本 `build.ps1` (推薦)

自動偵測 MSVC Build Tools，免手動開啟 Developer Command Prompt：

```powershell
.\build.ps1                  # 僅編譯 C DLL
.\build.ps1 -Standalone      # 編譯 DLL + Nuitka 目錄模式打包
.\build.ps1 -Onefile         # 編譯 DLL + Nuitka 單一 exe 模式打包
.\build.ps1 -Standalone -NoDll   # 僅打包 (跳過 DLL 編譯)
```

### 方式 2: 手動 MSVC 編譯

1. 開啟 **Developer Command Prompt for VS** (確保具備 MSVC x64 工具鏈)。
2. 執行：
   ```cmd
   cd NetRedirector
   call build_dll.bat
   ```
3. 編譯產出的 `NetRedirector.dll` 會自動輸出，覆蓋根目錄同名檔案即可生效。

### CI/CD

推送到 `main` 分支會自動觸發 GitHub Actions (`.github/workflows/build.yml`)：
編譯 C DLL → 語法/匯入 smoke test → Nuitka standalone 打包 → 上傳建置產物。

---

## ❓ 常見問題與故障排除 (FAQ)

1. **Q: 為什麼程式啟動時提示無法載入 WinDivert 驅動？**
   - A: 請確保以 **系統管理員身份 (Administrator)** 執行命令提示字元或 Python 腳本。部分防毒軟體可能會誤判 `WinDivert64.sys`，請加入排除清單。
2. **Q: 為什麼區域網路（LAN）內的印表機或共享資料夾無法存取？**
   - A: NetRedirector 內建「智慧局域網自動直連」功能，通常會自動放行私有網段。若仍有異常，請檢查規則分頁中是否有設定全域阻擋或覆蓋規則。
3. **Q: 支援遊戲加速或指定進程代理嗎？**
   - A: 支援。透過「進程攔截規則」指定遊戲主程式（如 `game.exe`）並套用 SOCKS5 代理即可實現精準遊戲加速。
4. **Q: VPN Gate 分頁抓不到節點或連線失敗？**
   - A: 抓不到節點時請確認本機可連線至 `www.vpngate.net` 再點擊「抓取節點」（節點清單偶爾會短暫不可用）。連線失敗屬正常流程，工具會自動換節點；若長期無可用節點，可調低「最低速度」門檻或取消「排除 port 443」。請確認已安裝簡體中文版 v4.44 的 SoftEther VPN Client，並已建立虛擬網卡。

---

## 📄 授權條款

本專案採用 [MIT License](LICENSE) 授權條款。

## 🤝 貢獻指南

歡迎提交 Issue 或 Pull Request 來共同完善 NetRedirector！
