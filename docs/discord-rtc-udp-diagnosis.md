# Discord RTC「沒有路由」診斷報告

日期：2026-10-21
症狀：Discord 語音顯示「RTC 連線中」，數秒後變成「沒有路由」（No Route）。
重現條件：攔截從頭開著 → 必失敗；先關攔截連上再開 → 可能維持正常；換 1.8.5 之前 → 正常。

## 一、復現結果

三組對照，同一台機器、同一支手機代理（192.168.1.178:1080）、同一時間。

| 組別 | 路徑 | 結果 |
| --- | --- | --- |
| A | `rtcprobe.exe`（設定內建 DIRECT 規則）→ 直連 | **4/4 STUN 回應**，來源正確，映射一致 `220.134.135.193:53431` |
| B | `python.exe`（catch-all PROXY）→ 引擎 UDP relay | **0/4**，全部逾時 |
| C | 繞過引擎，直接對代理做 SOCKS5 UDP ASSOCIATE | **2/2 STUN 回應**，映射一致 `49.215.23.152:63926` |

B 組另外補測 DNS over UDP（8.8.8.8:53）→ **timeout**。所以不是 STUN 被封，也不是特定目標的問題：
**引擎的 UDP relay 對所有目標都不通**。

代理本身（C 組）是好的，直連（A 組）也是好的。問題在引擎。

## 二、根因：UDP association 老化，且引擎沒有存活偵測

引擎日誌：

```
[17:04:18.577] UDP relay listening on port 33200 (IPv4 ok/IPv6 ok)
[17:04:18.577] UDP ASSOCIATE established with SOCKS5 proxy ID 1 (192.168.1.178:1080)
```

`Get-NetTCPConnection` 對照：引擎進程 64912 有一條到 192.168.1.178:1080 的連線，
**LocalPort 54635，CreationTime 2026/10/20 17:04:18** —— 與日誌完全吻合。

也就是說，這條 UDP ASSOCIATE 的控制連線已經存活 **16 小時**。期間日誌只出現過一次
`UDP relay: response no matching connection (213.170.135.8:10031)`（18:53），代表建立後
至少工作過一小時多，之後就再也沒有回程記錄。

SOCKS5 UDP ASSOCIATE 的 relay 埠（`BND.ADDR:BND.PORT`）生命週期由代理端決定，
通常綁在 TCP 控制連線的 NAT 映射上。手機熱點換手、基地台切換、NAT 表項逾時，都會讓
那個 UDP 埠失效 —— 但 **TCP 控制連線靠 keepalive 還活著**，所以引擎完全不知道。

`establish_udp_associate_with_config()` 建立 association 之後：

- `sendto()` 到失效的 relay 埠**不會報錯**（UDP 無連接），`send_fail_streak` 永遠是 0；
- `select()` 只監控 control socket 的可讀性，TCP 沒斷就不會清理；
- `UDP_TIMEOUT_MS`（10 分鐘）是 **connection entry** 的閒置超時，不是 association 的。

結果：引擎持續把每個 UDP datagram 送進一個黑洞，而且從不重試。Discord 的 STUN 與
媒體封包全部丟失 → ICE 永遠不完成 → 「沒有路由」。

## 三、為什麼 1.8.5 之後才出現

`7dfb45f`（1.8.5）修正了 UDP 歸因查表鍵：跳過 `dwOwningPid == 0` 的列。

- **1.8.4 及之前**：UDP 表第一列常是 `pid == 0`（通配綁定列、已關閉 socket），
  歸因失敗 → `check_process_rule()` 直接回 `g_unknown_process_action`（DIRECT）
  → Discord RTC 走**直連** → 打洞成功。
- **1.8.5 起**：跳過 `pid == 0` 找到真正的進程 → catch-all `* → PROXY` 匹配
  → RTC 走 **UDP relay** → 撞上第二節的黑洞。

所以不是 1.8.5 之後「新增了 bug」，而是 **1.8.5 讓 UDP 第一次真的走進 relay，
而 relay 的 association 存活偵測從來就不存在**。1.9.0 / 1.9.1 的引擎改動
（DNS 處置、IPv6 CIDR、日誌節流）與此無關 —— `NR_Core.c` 一行未改。

## 四、為什麼「先關攔截再開」會好

停止引擎會清空 `udp_associations`，再啟動時重新 ASSOCIATE，拿到一個**新的 relay 埠**，
黑洞消失。等到它再次老化，就又開始失敗 —— 這與使用者觀察到的「有可能維持一直是好的」
（不是每次都行）一致。

## 五、立即解法

1. **讓 Discord 的 UDP 走直連**（最快，且 RTC 本來就該直連才能打洞）：
   新增規則 `Name = Discord.exe`、`Protocol = UDP`、`Action = DIRECT`。
2. 或把 catch-all 規則的協定從 `BOTH` 改成 `TCP`，讓所有 UDP 預設直連。
3. 臨時緩解：每次發現 RTC 失敗時，停止再啟動一次攔截（重建 association）。

## 六、程式碼修復建議

在 `UDP_ASSOCIATION` 加兩個欄位：

```c
DWORD last_rx;        // 最近一次收到代理回程的時刻
UINT32 tx_since_rx;   // 自上次回程以來送出的 datagram 數
```

- 「app → 代理」分支送出成功時 `tx_since_rx++`；
- 「代理 → app」分支收到有效回程時 `last_rx = GetTickCount(); tx_since_rx = 0;`；
- 每次送出前檢查：`tx_since_rx >= 20 && now - last_rx > 15000` → `udp_assoc_drop(proxy_id)`，
  下一個 datagram 自然重建。

這個判據的好處是**不需要假設任何代理端的逾時長度**，只要求「送了 20 個以上卻在 15 秒內
零回程」才算死。單向 UDP（syslog 之類）會誤判，但那類流量本來就不在乎 relay 重建。

另一個更保守的選項：association 閒置超過 `UDP_ASSOC_MAX_IDLE_MS`（例如 5 分鐘）就主動重建，
成本是每個閒置代理每 5 分鐘多一次 TCP 握手。兩者可以並用。

## 七、附帶發現（不是本次主因，但同一個路徑）

`get_udp_reply_endpoint()`（`NR_State.c:249`）只用 `src_port + family` 當鍵，回傳
**最近使用的那筆 entry**。對「一個未 connect 的 UDP socket 同時對多個目標發送」
（WebRTC 的標準型態）會把回程來源還原成別的遠端。修好 association 之後，這個問題
會變成下一個瓶頸，建議一併改成用 `resolve_udp_response()` 已有的
「responder 位址 → app 端點」反查結果，而不是回頭用本地埠猜。

## 八、診斷工具

- `rtc_probe.py`：模擬 WebRTC 的單一 socket 多目標 STUN 探測，檢查回應來源與映射一致性。
- `socks5_udp_probe.py`：繞過引擎，直接對代理做 UDP ASSOCIATE，分離「代理問題」與「引擎問題」。

對照用法：

```
python rtc_probe.py                              # 走目前規則
.workbuddy-ai/probe/rtcprobe.exe rtc_probe.py    # 走 DIRECT 規則（需先把 python.exe 複製成 rtcprobe.exe）
python socks5_udp_probe.py 192.168.1.178 1080    # 繞過引擎
```

## 九、已實作的修復（2026-10-21）

### 驗證

使用者手動「整個關掉 NR 再開」後，同一支探針立刻回到 **4/4**，映射換成新的
`49.215.23.152:64115`（重啟前是舊埠，0/4）。老化假設確認。

### 改動

| 檔案 | 內容 |
| --- | --- |
| `NR_Common.h` | `UDP_ASSOCIATION` 加 `last_rx`、`tx_since_rx`、`rx_seen`；新增四個門檻常數 |
| `NR_Core.h` | 宣告純函式 `udp_assoc_is_silent()` |
| `NR_Core.c` | 實作判據；IPv4/IPv6 送出前檢查並 `udp_assoc_drop()`；送出成功 `tx_since_rx++`；收到回程歸零並設 `rx_seen` |
| `NR_Protocol.c` | 建立 association 時初始化三個欄位 |
| `tests/test_udp_assoc_liveness.c` | 新增 13 項測試（門檻邊界、雙向/單向分流、GetTickCount 環繞） |

### 判據

- **曾經有回程**（`rx_seen`）：送出 ≥ 20 個 datagram 且靜默 > 15 秒 → 判定 relay 埠已死，drop。
- **從未回程**（可能是單向流量）：≥ 200 個且 > 60 秒才 drop，避免每 15 秒重建一次。

### 測試

`test_udp_assoc_liveness` 13/13、`test_state` 68/68、`test_udp_rewrite` 22/22、
`test_rules` 33/33、`test_utils` 99/99、`test_filter` 32/32、`test_logging` 15/15 —— 共 282 項全綠。

### 部署

新 DLL 已建置於 `.workbuddy-ai/build/NetRedirector.dll`，原版備份為
`.workbuddy-ai/build/NetRedirector.dll.orig`。App 執行中時 DLL 被 map 住（`Device or resource busy`），
必須先完全關閉再覆寫 `IntegratedApp.dist/NetRedirector.dll`。

