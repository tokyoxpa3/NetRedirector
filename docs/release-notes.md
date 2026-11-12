# NetRedirector v2.1.0

## 補上 dual-stack 環境的最後一條漏洞：IPv6 不再從實體網卡洩漏

上一版讓 hub 正式支援 SOCKS5 UDP；這一版處理的是一個更早期、也更安靜的問題：
**在雙棧網路裡，IPv6 流量從來就沒有走過 VPN。**

症狀很隱晦 —— IPv4 的出口 IP 檢查完全正確，但支援 IPv6 的網站、DNS 查詢、
WebRTC 仍可能看到本機 ISP 派的真實位址。原因是 VPN Gate / SoftEther 公開節點
只提供 IPv4，系統的 IPv6 預設路由依舊指向實體網卡，任何 IPv6 連線都直接從
本機出去。

> ⚠️ **先講最重要的一句：這不是「讓 IPv6 變成日本 IP」。**
> VPN Gate 伺服器端沒有 dual-stack RA，根本不存在一個可以讓流量「來自」的
> 日本 IPv6 位址。本版做的是**「零 IPv6 洩漏」**：把本機 IPv6 關掉，瀏覽器的
> Happy Eyeballs 會自動退回 IPv4，於是所有流量都走 VPN。想要真正來自日本的
> IPv6，只能換有 IPv6 的日本出口（dual-stack WireGuard / 日本 SOCKS5），
> 用戶端做什麼都變不出來。

---

## 一、為什麼調路由、加規則、改 metric 都沒用

SoftEther 的 [issue #1163](https://github.com/SoftEtherVPN/SoftEtherVPN/issues/1163)
講的是同一件事：Windows client 的 `Win32AddRouteEntry()` 只安裝 IPv4 預設路由，
IPv6 沒有對應的路由管理。維護者在 2021 年說明這是刻意設計（hub option
`NoIPv6DefaultRouterInRAWhenIPv6`），後來的 PR #1443 / #1507 才補上 IPv6 route
management 並把預設改回允許遠端 IPv6 router —— **但那需要伺服端真的發 RA**，
公開 VPN Gate 節點沒有。

實機量測（19 張網卡）：

| 項目 | 結果 |
| :--- | :--- |
| `::/0` 路由 | **只有一條**，在 `乙太網路` (ifIndex 4) → `fe80::524f:...` |
| 實體網卡 IPv6 | `2001:b011:800b:3acc::/64` 全球位址 |
| 16 張 SoftEther VPN 網卡 | 全部只有 link-local `fe80::`，**沒有任何全球 IPv6** |
| IPv6 DNS | `fe80::524f:...`（on-link） |
| IPv6 interface metric | 實體 25、VPN 各 35（系統自動值） |

專案自己也有第二個洩漏點：`proxy_core.py` 對 IPv6 目標的 TCP 連線與
`ensure_v6_socket()` 都是 `bind(("::", 0))`，註解已寫明「VPNGate 節點是純
IPv4，沒有 IPv6 出口可綁」。所以即使引擎的 `* → PROXY` 規則把 IPv6 封包攔下來
送進 hub，hub 連線時仍查系統路由表，照樣從實體網卡出去。

順帶釐清一個常被聯想的開關：**「自動管理介面計量」與此無關**。那個功能只下
`Set-NetIPInterface -AddressFamily IPv4`，目的是讓實體網卡當 IPv4 主路由；
它完全沒碰 IPv6 metric，關掉或反轉都不會改變 IPv6 的路徑。

---

## 二、做法：停用實體網卡的 TCP/IPv6 綁定

入口在右上角 **⚙ →「IPv6 防洩漏設定...」**。

- **只列實體網卡**：PowerShell 用 `Get-NetAdapter -Physical`，再加上關鍵字黑名單
  （`softether` / `vpn` / `vmware` / `hyper-v` / `tap` / `tun` …）雙重保險。
  上述 19 張網卡的機器實測只列出 `乙太網路` 一張 —— 16 張 SoftEther VPN 與
  2 張 VMware 虛擬網卡都不會出現，也不需要停用（它們只有 `fe80::`）。
- **自己選網卡**：表格顯示網卡名稱、描述、連線狀態、IPv6 綁定狀態
  （`啟用 (會洩漏)` / `已停用 (已防護)`）與全球 IPv6 位址。首次開啟會自動勾選
  目前 IPv6 仍啟用、且有全球位址的網卡；點名稱或描述欄都能切換勾選。
- 按「啟用防護」前有確認對話框，執行
  `Disable-NetAdapterBinding -ComponentID ms_tcpip6`。連 ICMPv6 / RA /
  on-link IPv6 DNS 一起消失，比路由表或防火牆規則都乾淨。
- PowerShell 全部跑在背景執行緒，完成後以 Qt Signal 回 UI，不卡介面。

---

## 三、還原：這一版最花功夫的地方

`Disable-NetAdapterBinding` 寫入的是**持久化系統設定，重開機仍然有效**。
所以「還原」不能只是無腦把所有網卡 `Enable` —— 那會把使用者原本就自己關掉的
IPv6 打開。

- `config.json` 新增 `ipv6_guard.original`，記錄每張網卡**被停用前**的綁定狀態；
  「還原設定」只重新啟用原本就是啟用的網卡。
- 防護已啟用時又按一次「啟用防護」，`merge_original()` 會保留第一次快照，
  不會把狀態洗成「原本就是關閉」而導致還原失效。
- 狀態持久化 → 程式崩潰或被強制結束後，下次啟動仍可還原；啟動時若防護仍為
  啟用，會對「目前又被改回啟用」的網卡重新套用一次（驅動更新、系統還原都可能
  讓 IPv6 悄悄回來）。
- 可勾「結束程式時自動還原」，在關閉流程**同步**執行 —— 程式即將結束，背景
  執行緒會被砍掉，不能非同步處理。還原失敗時保留 `original` 供下次重試。
- 網卡名稱可能是中文、甚至含引號，因此整段腳本走 `-EncodedCommand`
  (UTF-16LE base64)，參數再以 UTF-8 base64 的 JSON 內嵌並由 PowerShell 端
  `ConvertFrom-Json` 解開，全程不把使用者資料拼進程式碼。

設定檔形狀（舊設定檔沒有此欄位時，會視為「防護關閉」，不影響既有組態）：

```json
"ipv6_guard": {
  "enabled": false,
  "adapters": [],
  "original": {},
  "restore_on_exit": false
}
```

---

## ⚠️ 注意事項與已知限制

- **影響整台電腦**：啟用後所有 IPv6 連線（含區網 IPv6、IPv6 DNS、VMware 虛擬
  網路的 v6）都會中斷，直到按「還原設定」。這是刻意取捨，不是 bug。
- 需要系統管理員權限（本程式載入 WinDivert 時原本就要求）。
- 這是「零 IPv6 洩漏」，不是「日本 IPv6」。對會同時檢查其他地區訊號的服務，
  IP 只是其中一環（時區、語言、帳號／門號地區等仍需一併留意）。
- 其餘 14 個語系（日／韓／德／法…）的新字串先以英文補齊，以通過
  「所有語系 key 集合一致」的檢查；後續版本再補完整翻譯。
- 驗證方式：`curl -4 https://api.ipify.org` 應為 VPN 出口 IP、
  `curl -6 https://api64.ipify.org` 應直接失敗，再用 `ipleak.net` 檢查
  DNS 與 WebRTC。

---

## 測試

- **`pytest` 278 passed**（v2.0.0 基準 246，新增 32 個：PowerShell 腳本組成、
  輸出解析、狀態／還原邏輯、Qt offscreen 對話框流程、設定序列化）。
- CI 等價檢查全綠：`ast.parse`、模組匯入 smoke test、
  `flake8 --select=F821` 未定義名稱檢查乾淨。
- **實機只讀驗證**：`list_adapters()` 正確回傳唯一一張實體網卡、
  `ipv6_enabled=True`、全球 IPv6 位址；Qt offscreen 冒煙測試確認
  「開對話框 → 背景讀取 → Signal 回填表格」整條非同步鏈路。
- 測試全部以 mock / 注入的 provider 取代 PowerShell，**不會更動系統設定**；
  開發期間也沒有真的停用任何網卡的 IPv6。
- **C 核心這次一行未改**，C 測試由 CI 執行。

## 升級方式

使用內建自動更新即可，版本號從 2.0.0 → **2.1.0**。若更新流程本身有問題，
直接下載本頁 zip 手動覆蓋（`NetRedirector.dll` 必須與執行檔同目錄）。

> 提醒：設定檔 `config.json` 放在程式目錄，IPv6 防護狀態也存在這裡。
> **手動換版本時請不要把整個資料夾刪掉重解壓**，否則設定（以及還原所需的
> `ipv6_guard.original`）會跟著消失；內建自動更新會自動保留它。
> 另外，若你跑的是打包版，只替換 `.py` 原始檔**不會生效**，請用釋出的 zip
> 覆蓋（或自行重新建置）。
