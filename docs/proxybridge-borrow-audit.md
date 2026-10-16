# ProxyBridge 上游借鏡審計

- **審計對象**：`InterceptSuite/ProxyBridge`（master，commit `02703a0`，Windows 核心版本字串 `4.0.13-Beta`）
- **比對對象**：本專案 `NetRedirector/NetRedirector/*.c`
- **方法**：clone 上游 → 逐模組讀核心 C（`Windows/src/`，11 檔約 5,900 行）→ 對本專案做同名功能的 `grep` / 逐行比對
- **判讀紀律**：本文把「我實際讀到的程式碼」與「推論」分開標註。標「推論」的地方請當假設看。
- **本報告狀態**：2026-10-03 已按實際產物核對並補上實測（§7 驗證記錄、§8 P1 研究記錄）。**P0 四項的程式碼已完成、測試通過、且已部署**（三份 dll 皆 240128 B 含新碼）。§2 的 P0 各節保留原始分析（為何要抄），實作狀態見 §7。

---

## 進度總覽（2026-10-03 01:2x 核對）

| # | 項目 | 程式碼 | 測試 | 部署 | 結論 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| P0-1 | WinDivertOpen 錯誤碼診斷 | ✅ 已實作 | ✅ | ✅ 已部署 | 完成 |
| P0-2 | filter 補 DHCPv6 546/547 | ✅ 已實作 | ✅ | ✅ 已部署 | 完成 |
| P0-3 | `WINDIVERT_PARAM_QUEUE_SIZE` | ✅ 已實作 | ✅ | ✅ 已部署 | 完成 |
| P0-4 | domain rule 時 flush DNS 快取 | ✅ 已實作 | ✅ | ✅ 已部署 | 完成 |
| P1-1 | 連線表加 hash index | ⬜ 不做 | 已量測 | — | **不做**（§8：O(M) 非 O(N)） |
| P1-2 | 新 SYN 清 pid 快取 | ⬜ 不做 | 已讀碼 | — | **不做**（§8.6：窗口次毫秒） |
| P1-3 | 折疊重複查表（新發現） | ✅ 已實作 | ✅ | ✅ 已部署 | 完成，省 21–25%（§8.5） |
| P1-4 | 喚醒閘控（新發現，**最大項**） | ✅ 已實作 | bench | ✅ 已部署 | 完成，省 ~350 ns/包（§9.1） |
| P1-5 | pid 重複解析（新發現） | ✅ 已實作 | ✅ | ✅ 已部署 | 完成，省 ~650 µs/次（§9.2） |
| P2-1 | IPv6 CIDR / IP 範圍比對 | 🟡 僅 IPv6 CIDR 已實作 | ✅ | ✅ 已部署 | IPv6 CIDR 完成（v1.9.1）；IPv4 CIDR／範圍、IPv6 範圍未動 |
| P2-2 | 可選代理 localhost | ❌ 未動 | — | — | 未開始 |
| P2-3 | 規則顯式排序 | ❌ 未動 | — | — | 未開始 |
| P2-4 | 規則匯入匯出 | ❌ 未動 | — | — | 未開始 |

> 一句話：**P0 四項已完成並部署；P1 原本兩項經實測判定不做（§8），但研究過程另外找到三項真正值得做的並已實作部署（§8.5、§9.1、§9.2）；P2 的 IPv6 CIDR（P2-1）已於 2026-10-16 實作、測試、部署並完成新舊 DLL 端到端對照（v1.9.1），其餘五項未動。**

---

## 0. 結論摘要

上游值得抄的東西**不多但很具體**，集中在四類：

| 類別 | 項目 | 建議 | 現況 |
| :--- | :--- | :--- | :--- |
| 支援成本 | WinDivertOpen 錯誤碼診斷 | **P0 直接抄** | 已實作，未部署 |
| 正確性 | 過濾條件漏排 DHCPv6（546/547） | **P0 補一行** | 已實作，未部署 |
| 穩定性 | `WINDIVERT_PARAM_QUEUE_SIZE` 未設 | **P0 補一行** | 已實作，未部署 |
| 功能缺口 | 域名規則啟動時 flush OS DNS 快取 | **P0 抄做法** | 已實作，未部署 |
| 效能 | 連線表是 O(N) 線性掃描 + 每封包加鎖 | **P1 最大單一問題** | 未開始 |
| 功能 | IPv6 CIDR / IP 範圍比對 | P2 | 未開始 |
| 功能 | 可選「代理 localhost」 | P2 | 未開始 |

同時有 **4 項他們的做法不該抄**（我們已經更正確），見 §4。

---

## 1. 上游架構速覽（我實際讀到的）

```
Windows/src/
├── ProxyBridge.c   1231 行  WinDivert 封包迴圈 + 生命週期 + 全域狀態
├── pb_rules.c      1173 行  規則比對（IP/Port/Domain/Process/規則 API）
├── pb_relay.c       811 行  本地 relay server + UDP relay + 雙向轉發
├── pb_conntrack.c   455 行  連線追蹤（正向表 + 反向表）
├── pb_socks5.c      441 行  SOCKS5（含 UDP ASSOCIATE）
├── pb_process.c     365 行  src_port → PID（GetExtendedTcpTable + 快取）
├── pb_proxy.c       360 行  代理設定查找
├── pb_dns.c         287 行  DNS snoop 快取（IP → hostname）
├── pb_util.c        253 行  socket 設定 / 逾時連線 / base64
├── pb_http.c        140 行  HTTP CONNECT
└── pb_internal.h    356 行  共用宣告
```

**關鍵常數**（`pb_internal.h`）

| 項目 | 上游值 | 本專案值 |
| :--- | :--- | :--- |
| 封包處理執行緒 | `NUM_PACKET_THREADS 1` | 1 receiver + N flow worker（同語意） |
| TCP relay port | 34010 | `g_local_relay_port` |
| UDP relay port | 34011 | `LOCAL_UDP_RELAY_PORT` |
| PID 快取 TTL | 30,000 ms | pid_map 3,000 ms（+ 權威 fallback） |
| 連線 stale timeout | 1,800,000 ms（30 分） | TCP 1 h / UDP 10 min |
| DNS snoop TTL | 300,000 ms（5 分） | 本專案另有一套 |
| 連線表 | 4096 bucket hash ×2（正向 + 反向） | **單向連結串列** |

---

## 2. 建議抄的項目

### P0-1　WinDivertOpen 失敗的錯誤碼診斷　★ 最高性價比

> **狀態：程式碼已完成**（`NetRedirector.c:784` `log_windivert_open_failure()`，呼叫點 `:943`）。測試涵蓋於 `test_filter`。**已部署（2026-10-03 01:25，三份 dll 皆 240128 B 含新碼）。**

上游把 `WinDivertOpen` 失敗的 `GetLastError()` 逐一映射成**可執行**的訊息（`ProxyBridge.c:1007-1028`）：

| 錯誤碼 | 上游訊息重點 |
| :--- | :--- |
| 2 `ERROR_FILE_NOT_FOUND` | `WinDivert64.sys` 被防毒隔離/刪除 → 加白名單後重裝 |
| 5 `ERROR_ACCESS_DENIED` | 非管理員 |
| 577 `ERROR_INVALID_IMAGE_HASH` | 驅動簽章驗證失敗，`sys` 可能被改過 |
| 1058 `ERROR_SERVICE_DISABLED` | 前次安裝殘留的驅動註冊機碼被標為停用 → 刪 `HKLM\SYSTEM\CurrentControlSet\Services\WinDivert` |
| 1275 `ERROR_DRIVER_BLOCKED` | 被 Windows 安全策略/防毒 BYOVD 防護擋下 |

本專案目前只印 `Failed to open WinDivert (%lu)`。這五種失敗在實務上都會發生，且使用者拿到的是一個裸數字——**直接照抄這張表，成本 20 行，換掉一整類客服往返。**

### P0-2　過濾條件漏排 DHCPv6（真實缺口）

> **狀態：程式碼已完成**（`NetRedirector.c:765-771`，IPv6 子句已改為排除 546/547）。`test_filter` §6 以「凍結的舊子句 vs 新子句」對照證明行為已改變（32/32）。**已部署（2026-10-03 01:25，三份 dll 皆 240128 B 含新碼）。**

上游 filter（`ProxyBridge.c:989-1000`）在 v4/v6 分支分別排除 DHCP：

```
udp.SrcPort != 67  and udp.DstPort != 67  and udp.SrcPort != 68 and udp.DstPort != 68
udp.SrcPort != 546 and udp.DstPort != 546 and udp.SrcPort != 547 and udp.DstPort != 547
```

本專案 `NetRedirector.c:704-721` 的 **IPv6 分支寫的是 67/68（IPv4 的埠號），沒有 546/547**。所以 DHCPv6 封包仍會被攔截進 user mode。

- 我實際確認：`NR_RuleEngine.c:176` 會把 multicast/special IPv6 判成 DIRECT，所以**不會誤擋**，只是白白付一次 user-mode round trip（queue → worker → checksum → WinDivertSend）。
- 修法：IPv6 子句改成排除 546/547。**低風險、一行。**

### P0-3　`WINDIVERT_PARAM_QUEUE_SIZE` 未設定

> **狀態：程式碼已完成**（`NetRedirector.c:973-975`，三個參數都設、結果合併成單次回報）。**已部署（2026-10-03 01:25，三份 dll 皆 240128 B 含新碼）。**

上游設三個參數（`ProxyBridge.c:1040-1048`），註解明確寫了踩過的坑：

```
QUEUE_LENGTH = 16384      // 佇列封包數上限（32–16384）
QUEUE_TIME   = 2000       // 封包在佇列等待上限 ms（100–16000，預設 2000）
QUEUE_SIZE   = 33553920   // 佇列總位元組上限（65535–33553920）
```

他們註解記錄：舊值 `QUEUE_TIME = 8` **低於允許最小值 100**，在持續上傳下造成大量丟包，直接表現為「上傳吞吐掉 40–60%」。

本專案已設 `QUEUE_LENGTH=16384` 與 `QUEUE_TIME=2000`（正確），但**沒設 `QUEUE_SIZE`**。突發大封包仍可能撞到位元組上限。補上即可。

### P0-4　域名規則啟動時 flush Windows DNS 解析快取　★ 實質功能缺口

> **狀態：程式碼已完成**（`NR_Utils.c:749` `hosts_field_has_domain()`、`:791` `flush_dns_resolver_cache()`；鉤點在 `NetRedirector.c` 的 AddRule `:95`、EditRule `:127`、批次載入 `:141/:151`、`:232`、`has_domain_rule()` `:460`、`flush_dns_if_domain_hosts()` `:476`、`Start` `:1015`）。`test_utils` 新增 10 個案例（73/73）。**已部署（2026-10-03 01:25，三份 dll 皆 240128 B 含新碼）。**

上游 `pb_dns.c:276-286` + `ProxyBridge.c:938-941`：

```c
// 啟動時若已存在 domain rule，flush OS 解析快取，
// 讓應用程式重新在網路上解析 → 我們的 port-53 snoop 才能抓到 IP→hostname。
if (g_has_domain_rules) flush_dns_resolver_cache();
// 動態 LoadLibrary("dnsapi.dll") 取 DnsFlushResolverCache，避免硬相依
```

**為什麼這對我們重要**：本專案的 `*.google.com` 這類萬用子網域規則，唯一可靠的來源是攔截到的 DNS 回應（`dns_snoop_matches_suffix`，`NR_Utils.c:569-598`）。本專案背景執行緒 `dns_refresh_worker`（`NetRedirector.c:436-470`）只做**正向**解析規則裡的 host（`refresh_rule_dns`），**不做反查**。

因此：若某域名在規則建立前（或程式啟動前）就已被 Windows 解析器快取，應用程式不會再發 DNS 查詢 → snoop 永遠學不到 `mail.google.com → 1.2.3.4` → 該萬用規則**靜默失效**，直到 OS 快取 TTL 到期。

- 上游的做法（flush 一次，逼應用重新上網解析）**直接解掉這個情境**。
- 建議落點：`NetRedirector_Start()` 內（若已有 domain rule）、以及 `NetRedirector_AddRule/EditRule` 引入新 domain rule 時。
- 同樣用動態載入 `dnsapi.dll`，不新增連結相依。

### P1-1　連線表：O(N) 線性掃描 + 每封包加鎖（最大單一效能問題）

**上游做法**（`pb_internal.h:205-237` + `pb_conntrack.c`）：

- 正向表 `connection_hash_table[4096]`（key = src_port）、反向表 `connection_rev_table[4096]`（key = 原始目的地），各用 `SRWLOCK`。
- 更關鍵的是 **per-source-port 決策位圖**：

```c
volatile LONG port_decided_bitmap[2048];  // 8 KB
volatile LONG port_direct_bitmap[2048];   // 8 KB
// 一旦某個 source port 被判為 DIRECT：
//   port_is_decided() = 讀 1 個 bit  → 後續每個封包直接 WinDivertSend
//   「one bitmap read, 5 cycles + WinDivertSend, with zero kernel calls」
```

**本專案做法**：`NR_State.c` 的 `connection_list` 是**單向連結串列，沒有 hash、沒有上限**；`NR_Core.c:223` 對每個 outbound TCP 封包呼叫 `is_connection_tracked()`，而它會 `EnterCriticalSection(&lock_connections)` 後**全表線性掃描**（`NR_State.c:140-167`）。

- 這是**每個封包**的成本，不只是每個新連線。大量並行連線 + 高封包率（遊戲、串流）時是 O(N) × pps，且全部序列化在同一把鎖上。
- 注意：本專案的 key `(src_port, family, orig_dest)` **比上游正確**（上游只用 src_port，同一個 socket 對兩個目的地時會互相污染；本專案註解已說明為何刻意加目的地）。**不要為了效能退回他們的 key。**
- 建議（原始分析）：**保留 key，加 hash index**（成本最低、零語意變更）。若還要更快，可再加一個「已判定為 DIRECT 的 (src_port,dest) 位圖」當**提示**——但必須在 FIN/RST 與 port 回收時清除，否則會拿舊決策套新連線（這正是上游用 `port_clear` + `remove_cached_pid` 在補的洞）。

> **已實測，結論：不要做。** 見 **§8**。上面「O(N) × pps」的框架對**命中**路徑是**錯的** —— move-to-front 讓掃描長度是 **O(M)（活躍流數）** 而不是 O(N)，且現實負載下總成本 < 2.5% 單核。唯一值得動的是另一件事：封包路徑對同一個 key **查了兩次表**（§8.5）。

### P1-2　收到新 SYN 時主動清除該 port 的 PID 快取

上游 `ProxyBridge.c:666-672`：新 SYN（`Syn && !Ack`）時 `remove_cached_pid(src_ip, src_port, FALSE)`。理由：Windows 積極回收 ephemeral port，新連線可能沿用舊 port，若不 evict，會**拿前一個 process 的規則決策套到新連線上**（可達 `PID_CACHE_TTL_MS` = 30 秒）。

本專案的 `NR_PidMap.c` 用 `ambiguous` 旗標 + 3 秒 TTL 處理埠回收，且 TTL 到期即退回權威的 `GetExtendedTcpTable`——**方向是 fail-closed 的，比上游安全**。唯一差別是「3 秒內若 CLOSE 事件遺失，可能答錯」。加一條「新 SYN → 清該 port 條目」可以讓視窗縮到零，成本極低。

> **已讀碼評估，結論：價值接近零，不做。** 見 **§8.6**。`ambiguous` 的觸發條件是「不同 pid 對同一 port 插入」，而新連線的 `BIND`/`CONNECT` 事件在 SYN 上網前後就會發生 —— 殘餘窗口是**次毫秒級**，不是 3 秒。

---

## 3. 可選 / 功能面

### P2-1　IPv6 CIDR 與 IP 範圍比對

> **狀態（2026-10-16）：IPv6 CIDR 已完成並部署（v1.9.1）**。`NR_Utils.c` 新增
> `match_ipv6_cidr()`（`InetPtonA` + `prefix_to_mask`，沿用本機介面 LAN 判定既有的遮罩
> 函式），`match_ip_pattern6()` 在 domain 分支之前先判 `/`。`test_utils` 新增 25 個案例
> （73→98）。**IPv4 CIDR／IPv4 範圍／IPv6 範圍仍未做。**
>
> 端到端驗證（`.workbuddy-ai/ab/run_191_ab.py`，新舊 DLL 對照）：規則
> `* / 2001:4860::/32 / * TCP -> PROXY` 下 `curl -6 http://[2001:4860:4860::8888]:9999/`
> 在**新版**被判 `Proxy (TCP)`、代理收到 `ATYP_IPV6` 且 curl 得 200（rc=0）；
> **舊版**同規則同流量判 `Direct (TCP)`、代理零記錄。另以不涵蓋的 `2001:db9::/32`
> 作對照，同樣 `Direct (TCP)`。
>
> 順帶修掉一個被 CIDR 放大的既有缺陷：`hosts_field_has_domain()` /
> `refresh_rule_dns()` 用 `is_ip_like_pattern()`（它問的是「是不是點分 IPv4」）
> 當「是不是域名」的判準，所以任何含 `:` 或 `/` 的 token 都被當成域名 ——
> 既有的 IPv6 精確位址就已經踩到，CIDR 只是讓它更常見。後果是每次新增／編輯
> 這類規則都會**多一次全機 DNS 解析快取清除**（`flush_dns_resolver_cache`）
> 外加兩次註定失敗的解析。已抽成 `is_domain_token()`（`:` 或 `/` 直接判為
> 位址，不可能是主機名）並在兩處改用。

| 樣式 | 上游 | 本專案 |
| :--- | :--- | :--- |
| IPv4 octet 萬用 `192.168.*.*` | ✅ | ✅ |
| IPv4 範圍 `10.0.0.1-10.0.0.50` | ✅ | ❌ |
| IPv4 CIDR `10.0.0.0/8` | ❌ | ❌ |
| IPv6 精確 `2001:db8::1` | ✅ | ✅ |
| IPv6 CIDR `2001:db8::/32` | ✅ | ✅ |
| IPv6 範圍 `2001:db8::1-2001:db8::ff` | ✅ | ❌ |
| 埠範圍 `8000-9000` | ✅ | ✅ |

上游實作在 `pb_rules.c:170-234`（`match_ip_pattern_v6`），用 `inet_pton` + 前綴位元遮罩，約 60 行。

本專案 `NR_Utils.c` 的 IPv6 比對在處理完 domain 規則後，原本只剩 `_stricmp(pattern, addr_str)` 的**字串精確比對**。IPv6 規則沒有 CIDR 幾乎沒法寫（一個 /64 要列 2^64 個位址），故先補 CIDR。

⚠️ **`10.0.0.0/8` 這種 IPv4 CIDR 目前是陷阱**：`is_ip_like_pattern()` 看到 `/` 就
回 FALSE，於是它會被當成**域名**去解析，解析必然失敗，規則變成永不匹配且完全靜默。
IPv6 分支現在有 `/` 早退，IPv4 分支還沒有 —— 要動 IPv4 CIDR 時連這條一起處理。

### P2-2　可選「代理 localhost」

上游把 loopback 納入攔截範圍（filter 含 `loopback`），再用 `LocalhostViaProxy` 開關（預設關）決定是否走代理；關閉時 `127.x` / `::1` 一律 DIRECT。

本專案在 **filter 層直接排除 127/8 與 ::1**（`NetRedirector.c:710,717`），所以本機目標**永遠無法被代理**。多數情況這是對的（上游 README 也說預設該這樣），但若想支援「代理跑在本機、要把 localhost 目標送出去」或本機 MITM 測試，就需要改成上游那種「攔截 + 開關」的形式。

> 注意：這與「代理伺服器位址在本機」不同。本專案 `collect_proxy_endpoints()`（`NetRedirector.c:676-702`）已把**已設定的代理端點動態排除**在 filter 外——這點**我們比上游完整**（上游只排除自己的 relay port）。

### P2-3　規則顯式排序（可選）

上游提供 `ProxyBridge_GetRulePosition` / `MoveRuleToPosition`（`pb_rules.c:1040-1141`）+ GUI 拖曳。

本專案 `NR_RuleEngine.c` 的比對策略與上游**幾乎一致**（具體規則先掃、全萬用 `*` 規則留到最後當 fallback），差別是本專案多一層「PID 規則優先」。所以排序只影響同優先級規則之間的順序。價值中等，取決於是否遇到「兩條同等具體的規則互相搶」的客訴。

### P2-4　CLI 與 profile 匯入匯出

上游有原生 C CLI + `.pbprofile`（JSON）匯入匯出，GUI 也有 `PB_ProfileImport/Export`。本專案 `tabs_rules.py` **沒有規則匯入匯出**。若之後要做自動化部署、多機同步規則、或讓使用者分享規則集，這是最省事的切入點（本專案已有 `config_store.py` / `secure_config.py` 可複用）。

---

## 4. 不要抄的（我們已經更正確）

| 上游做法 | 為什麼不要抄 |
| :--- | :--- |
| **Relay socket pin `SO_RCVBUF/SO_SNDBUF = 4 MB`**（`pb_relay.c:613-614`） | 本專案**實測**：在 Windows 上「呼叫 `setsockopt(SO_RCVBUF)`」這個動作本身會**關掉 receive-window auto-tuning**，反而掉速。同機同檔交錯 6 輪：pin 64 KB → avg 230.9 Mbps；**不設 → avg 281.0 Mbps**；pin 256 KB → 279.2 Mbps。本專案 `NR_Core.c:838-856` 已移除該設定並留下量測記錄。**不要「為了保險」加回去。** |
| **連線表只用 `src_port` 當 key** | 同一個 socket 對兩個目的地時會互相污染。本專案刻意用 `(src_port, family, orig_dest)`（`NR_State.c:14-30` 有完整理由）。**抄 hash 結構，別抄 key。** |
| **統一的 30 分鐘 stale timeout** | 本專案 TCP 1 小時 / UDP 10 分鐘。上游自己的註解就說 stale timeout 必須大於 relay keepalive（他們 5 分鐘）否則空閒連線會被中途回收、造成「數小時的靜默降級」。本專案 keepalive 20 秒 vs TCP timeout 1 小時，餘裕更大。 |
| **filter 加 `not impostor`** | WinDivert 官方文件：「一個封包在**同一優先級只被 divert 一次**」——自己的 handle 不會重收自己注入的封包。本專案只有一個 network-layer handle（priority 123），價值接近零。上游的註解把效果說得比文件支持的大。**可加但不必加**，屬防禦性冗餘。 |

---

## 5. 我們領先的地方（別被上游「改回去」）

這幾項本專案明顯更強，寫在這裡是為了避免以後回頭看上游時誤以為自己漏了什麼：

1. **PID 解析**：本專案用 WinDivert **SOCKET 層事件**維護 `(protocol, port) → pid`（`NR_PidMap.c`，含 `ambiguous` 防埠回收誤判、`SNIFF|RECV_ONLY` 才不會卡死全機 socket 建立的實測記錄），權威 fallback 是 `GetExtendedTcpTable`。上游每個新連線第一次都要付一次 `GetExtendedTcpTable` 全表列舉（本專案註解估 ~650 µs）。
2. **代理端點動態排除**：本專案把使用者設定的每個代理位址寫進 filter 的排除子句（含 IPv6），上游只排除自己的 relay port。
3. **Relay port 防火牆處理**：本專案 Start 時自動替 33100/33200 加入站允許、Stop 時移除（README FAQ #6 那個 21 秒黑洞）。**上游完全沒有防火牆處理**（`grep -i "netsh|INetFw|FirewallPolicy"` 全空）。
4. **Relay port pre-flight probe**：本專案 Start 前先 bind 一次 TCP+UDP relay port，佔用就中止並回報。**上游沒有**（`grep -i probe` 全空），它的 `bind` 在執行緒裡失敗只印一行 log，`Start()` 仍回報成功 → 所有走代理的連線黑洞。
5. **執行緒可控關閉**：本專案有 relay pair 註冊表，`Stop()` 對每個 pair `shutdown(SD_BOTH)` 解鎖 recv。上游靠 ref-count + shutdown，同構；但本專案多了「停止時主動中斷」這條路徑。

---

## 6. 建議行動順序

| # | 項目 | 預估規模 | 風險 | 狀態 |
| :--- | :--- | :--- | :--- | :--- |
| 1 | WinDivertOpen 錯誤碼診斷表 | ~20 行 | 無 | ✅ 已實作 / ❌ 未部署 |
| 2 | filter 補 DHCPv6 546/547 排除 | 1 行 ×2 處 | 無 | ✅ 已實作 / ❌ 未部署 |
| 3 | `WINDIVERT_PARAM_QUEUE_SIZE` 設最大值 | 1 行 | 無 | ✅ 已實作 / ❌ 未部署 |
| 4 | 有 domain rule 時 flush OS DNS 快取 | ~15 行 | 低 | ✅ 已實作 / ❌ 未部署 |
| 5 | 新 SYN 時清 pid_map 該 port 條目 | ~10 行 | 低 | ⬜ **不做**（§8.6） |
| 6 | 連線表加 hash index（保留原 key） | 中等 | 中（需回歸測試） | ⬜ **不做**（§8） |
| 6b | 折疊重複查表（TCP+UDP 各一處） | ~10 行 | 低 | ⬜ 可做（§8.5） |
| 7 | IPv6 CIDR + IP 範圍比對 | ~60 行 | 低 | ⬜ 未開始 |
| 8 | 規則匯入匯出（GUI） | 中等 | 低 | ⬜ 未開始 |

1–4 的程式碼已寫完並通過測試，**且已於 2026-10-03 01:25 部署**（三份 dll 皆為 240128 B、都含新碼，見 §7.3/§7.4）。
5–6 經實測**判定不做**（§8）；6b 是研究過程新發現的小改動，約 10 行、低風險、省 21–25%。7–8 尚未開始。

---

## 7. 驗證記錄（2026-10-03 01:2x 實測）

這一節存在的理由：本報告初稿寫於 00:46，P0 的程式碼在 00:55 才落地。**報告的「建議」與「現況」因此在幾十分鐘內就分岔了**——不重新核對，下一個讀者會去重做已經做完的事。以下每一條都是實跑/實讀的結果，不是轉述。

### 7.1 程式碼落點（grep 確認存在）

| 項目 | 檔案:行 | 證據 |
| :--- | :--- | :--- |
| P0-1 | `NetRedirector.c:784` `log_windivert_open_failure()`，呼叫 `:943` | `case 577 / 1058 / 1275` 五個分支齊全 |
| P0-2 | `NetRedirector.c:765-771` | IPv6 UDP 子句含 `udp.DstPort != 546` / `!= 547` |
| P0-3 | `NetRedirector.c:973-975` | `QUEUE_LENGTH 16384` / `QUEUE_TIME 2000` / `QUEUE_SIZE 33553920` 三者齊 |
| P0-4 | `NR_Utils.c:749` `hosts_field_has_domain()`、`:791` `flush_dns_resolver_cache()` | `LoadLibraryA("dnsapi.dll")` + `GetProcAddress("DnsFlushResolverCache")`，無新增連結相依 |

### 7.2 測試（重編譯後實跑，非引用舊結果）

以 `NetRedirector/tests/run_tests.ps1` 重新編譯**全部**測試並執行：

```
test_dns_snoop    29/29
test_filter       32/32   ← 含 §6 DHCPv6（凍結舊子句 vs 新子句對照）、§7 IPv6 不得過度排除
test_lock_stress   1/1
test_rules        24/24
test_state        62/62
test_udp_rewrite  22/22
test_utils        73/73   ← 含 hosts_field_has_domain() 10 案例
------------------------------------------------
合計             243 項全數通過
```

`test_filter` 裡「old clause captured DHCPv6, new clause excludes it (behaviour changed)」這一條是**鑑別性測試**：它會區分「改了」與「沒改」，不是只驗證新子句存在。

### 7.3 編譯產物是否真的含新碼（位元組比對）

以 Python 讀 bytes 直接比對三個字串標記（不用 `strings`——它對非 ASCII 會說謊；這幾個標記是 ASCII，但仍以位元組計數為準）：

| 檔案 | 大小 | 時間 | `BYOVD protection` | `stale WinDivert service entry` | `udp.DstPort != 546` |
| :--- | ---: | :--- | :---: | :---: | :---: |
| `NetRedirector/NetRedirector.dll` | 240128 | 10-03 00:55 | 1 | 1 | 1 |
| `NetRedirector.dll`（repo 根） | 237568 | 10-02 06:24 | **0** | **0** | **0** |
| `IntegratedApp.dist/NetRedirector.dll` | 234496 | 09-27 20:44 | **0** | **0** | **0** |

→ 新碼**只存在於編譯輸出**，兩個會被載入的位置都還是舊的。

> 上表是 **P0 當時**（10-03 00:55，240128 B）的快照，用來證明「部署前新碼沒進到被載入的位置」。
> 加入 §9 的三項改動後，三份 dll 皆為 **240640 B** 且標記齊全（見 §9.4）。

### 7.4 部署狀態（P0 曾「寫完但等於零效果」的原因）

核對時（01:2x）的狀態：

- 執行中的行程 **pid 69284（`C:\dev\Python311\python.exe`，10-02 06:26 啟動）已載入 `d:\workspace\4Games\NetRedirector\NetRedirector.dll`**。
- 也就是說：**App 讀的是 repo 根目錄那份**（`IntegratedApp.py:123` 用相對路徑 `"NetRedirector.dll"`，工作目錄即根目錄），而不是 `IntegratedApp.dist/` 那份。初稿記憶裡「dist 才是執行中載入的那份」的說法**與實測不符，以此處為準**。
- 這個 pid 正是 `build.ps1` 覆寫根目錄 dll 失敗的原因（檔案被鎖）。
- 因此在關閉該行程之前，P0 四項在實際使用上**等於零效果**。

**後續（01:25，使用者關閉 App 後）**：

1. 確認無任何行程載入 `NetRedirector.dll`（鎖已釋放）。
2. `build.ps1` 重新編譯 → **成功**複製到根目錄（`DLL 編譯成功！已複製到 NetRedirector.dll`）。
3. 手動把新 dll 同步到 `IntegratedApp.dist/`（等價於 Nuitka 打包會做的那一步，省下整個重打包）。
4. 複驗位元組標記：**三份皆 240128 B，5 個標記全部 = 1** → 部署生效。

> 教訓：`build.ps1` 只更新**前兩份**（編譯輸出 + 根目錄），**不會**碰 `IntegratedApp.dist/` —— 那份只有 Nuitka 打包才會更新。從源碼跑的實例吃根目錄，打包版吃 dist，**兩邊都要換才算真的部署完**。

### 7.5 未動的項目（grep 回空 = 有效證據）

| 項目 | 搜尋 pattern | 結果 |
| :--- | :--- | :--- |
| P1-1 連線表 hash | `NR_State.c` 內 `hash` / `bucket` / `CONNECTION_INFO *x[]` | 空；`connection_list` 仍為單向串列（22 處引用），`is_connection_tracked()` 仍線性掃描 |
| P1-2 新 SYN 清 pid 快取 | `remove_cached_pid` / `invalidate_pid` / 封包內 `Syn && !Ack` 判斷 | 空（`Syn` 的命中全是關於 connect 逾時的註解，與此項無關） |
| P2-1 IPv6 CIDR 規則比對 | `NR_Utils.c` / `NR_RuleEngine.c` 內 `inet_pton` / `cidr` | 空。`NR_Utils.c:1045-1116` 的 prefix 程式碼是**本機介面 LAN 判定**，不是規則比對，別誤認 |
| P2-4 規則匯入匯出 | `tabs_rules.py` 內 `import` / `export` | 空 |

> 附帶：`NR_Core.c:388-415` 有一個 `flow_hash()`（FNV-1a 5-tuple，用於把封包分派到 `FLOW_WORKERS` 條 worker 佇列）——**那是 worker 分派，不是連線表索引**，與 P1-1 無關。看到 `hash` 別誤判 P1-1 已完成。

---

## 8. P1 研究記錄（2026-10-03 實測）

方法：新增 `NetRedirector/tests/bench_conn_contention.c`（MinGW gcc，連結**真實的** `NR_State.c`，所以走訪包含 critical section 本體）。它刻意讓三個成本**分開出現**：

| 想量的東西 | 怎麼讓它單獨出現 |
| :--- | :--- |
| 掃描長度 | 變化 M（活躍流數）與 N（串列總長），看走訪節點數跟著誰 |
| 鎖的序列化 | 變化執行緒數，看**總**吞吐量（不是單次延遲） |
| move-to-front 的寫入 | 對照「預熱後唯讀走訪」vs「真函式（含寫入）」 |

⚠️ **第一版對照組是錯的**：拿「不做 MTF 的唯讀走訪」當對照，結果它永遠不會自我組織，熱流一直卡在串列尾端（1941 ns vs 77 ns）——量到的是「沒有自我組織」而不是「沒有寫入」。**修正：兩組都先預熱**（先對熱流跑幾輪真實查詢把他們移到前端）再量。這是本節唯一一個「先寫錯再修」的地方，留著當紀錄。

### 8.1 掃描長度是 O(M)，不是 O(N)

3 執行緒，平均每次查訪的節點數：

| N \ M | M=8 | M=64 | M=256 | M=1024 |
| :--- | ---: | ---: | ---: | ---: |
| 64 | 7.9 | 53.6 | — | — |
| 256 | 7.9 | 54.3 | 170.8 | — |
| 1024 | 7.9 | 54.0 | 170.1 | 842.7 |
| 4096 | 7.9 | 54.4 | 165.7 | 850.8 |

**N 從 64 漲到 4096（64 倍），M=64 的走訪節點數完全不變（≈54）。** 走訪長度只跟 M 有關。
→ 原報告「O(N) × pps」對**命中**路徑是錯的：move-to-front 讓串列按最近使用排序，熱流集中在頭部，成本是 O(活躍流數)。

### 8.2 加執行緒會讓**總**吞吐量下降（真實現象）

N=1024, M=64, 全部命中：

| 執行緒 | 真函式 ns/op | 總 ops/s | 相對 1 執行緒 | 唯讀(無寫入) ns/op | 相對 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 77.0 | 12,984,905 | 1.00x | 41.9 | 1.00x |
| 2 | 124.1 | 8,054,969 | 0.62x | 68.2 | 0.61x |
| 3 | 164.0 | 6,099,339 | **0.47x** | 76.4 | 0.55x |
| 4 | 175.8 | 5,686,733 | 0.44x | 91.1 | 0.46x |
| 8 | 197.5 | 5,063,154 | **0.39x** | 100.7 | 0.42x |

- **加執行緒不會增加總吞吐量，反而減少**（3 條只剩 0.47x）。這不是「序列化後打平」，是**比單執行緒更差** —— 全域鎖的 cache line 在核心間彈跳，加上每次命中的 MTF 寫入讓所有 worker 互相弄髒同一批節點。
- 即使把寫入拿掉（唯讀欄），3 條也只有 0.55x：**鎖本身就是瓶頸**，寫入只是讓它更糟。
- **真實分派（worker 各帶不相交的流，即 flow hash 的行為）並沒有比較好**：M=1024 時 shared 2727.8 ns vs disjoint 2882.0 ns。因為每個 worker 的 MTF 會把自己那批流推到前面、把別人的擠下去，前端互相打架。

### 8.3 move-to-front 的寫入讓每次命中貴約 1.8 倍

預熱後對照：1 執行緒 41.9 ns（唯讀）vs 77.0 ns（含 MTF 寫入）；8 執行緒 100.7 vs 197.5 ns。
**但這不是「把 MTF 拿掉就好」** —— MTF 正是讓掃描維持 O(M) 的機制，拿掉會退化成 O(N)（見 8.1：M=64 / N=4096 時會從 54 節點變成平均數千）。**兩者不能分開考慮。**

### 8.4 現實負載下的預算：可以忽略

N=1024, M=64（一般桌面／瀏覽器）：

| 封包率 | 1 執行緒 | 3 執行緒 |
| ---: | ---: | ---: |
| 23,333 pps（≈280 Mbps） | 0.185% 單核 | 0.388% |
| 80,000 pps | 0.634% | 1.331% |
| 150,000 pps | 1.190% | 2.496% |

即使 150k pps 也只吃 2.5% 單核。**與 `process_packet()` 每次改寫都要付的 `WinDivertHelperCalcChecksums`（320 ns/包）相比是零頭。**

唯一例外是**大量並行流**：M=512 → 1243 ns、M=1024 → 2730 ns（3 執行緒）。torrent 類或大量 peer 的遊戲在 M≈1000、50k pps 下約 13% 單核。**但這是利基情境，沒有實測到使用者抱怨。**

### 8.5 唯一值得動的：封包路徑對同一個 key 查了兩次表

`NR_Core.c:223-226`（TCP case 2）：

```c
else if (is_connection_tracked(ntohs(tcp_header->SrcPort), family, dst_addr)) {
    UINT32 proxy_id = 0;
    get_connection(src_port, family, dst_addr, NULL, NULL, NULL, &proxy_id, NULL);
```

兩次呼叫的**匹配條件逐字相同**（`src_port` + `!is_udp` + `family` + `memcmp(orig_dest_addr)`），第二次只是為了拿 `proxy_id`。UDP 分支（`:139`/`:142`）是同一個形狀。
`get_connection()` 本來就同時回傳「找到沒」與 `proxy_id`，所以 `if (get_connection(...))` 就是等價的判斷 —— **而且它會更新 `last_activity`，`is_connection_tracked()` 不會**（目前是靠緊接著的第二次呼叫才更新到）。

實測（N=1024, M=64，全部命中）：

| 執行緒 | 現在（兩次查表） | 建議（一次） | 省下 |
| ---: | ---: | ---: | ---: |
| 1 | 104.0 ns | 82.2 ns | 21% |
| 3 | 233.7 ns | 175.3 ns | 25% |

省下的**不是**一半的掃描（第一次查詢已把條目移到最前面，第二次幾乎不用掃），而是**少一次鎖取得 + 少一次 MTF 寫入 + 少一次呼叫**。

- 落點：`NR_Core.c` TCP case 2（`:223-235`）與 UDP 分支（`:139-145`）。
- 規模：約 10 行。風險：**低** —— 匹配條件相同；且若條目被別條執行緒併發移除，新寫法會直接跳過改寫（比現在更正確，現在會照樣呼叫 `remove_connection`）。
- 值不值：省 25% 的「本來就只佔 2.5% 單核」→ 約 0.6% 單核。**收益很小，但成本也幾乎為零。**
- **已於 2026-10-03 實作並部署**（見 §9.4）。

### 8.6 P1-2：殘餘窗口是次毫秒，不是 3 秒

原報告說「3 秒內若 CLOSE 事件遺失，可能答錯」。實際讀 `NR_PidMap.c`：

- `ambiguous` 的觸發是 **`pid_map_insert()` 看到不同 pid 對同一 (proto, port) 插入**（`NR_PidMap.c:148-164`），不是等 TTL。
- 新連線的 `BIND`/`CONNECT` 由 `bind()`/`connect()` 產生，與 SYN 上網是同一條 syscall 路徑的前後腳。所以新 socket 一被觀察到，舊條目立刻變 `ambiguous` → `pid_map_lookup()` 回 0 → **fail-closed 退回權威的 `GetExtendedTcpTable`**。
- 真正的窗口是「SYN 封包被 worker 處理」早於「`BIND`/`CONNECT` 事件被 `pid_map_worker` 消費」的那一段 —— 次毫秒級，且只影響**新連線的規則判定**（已追蹤的連線根本不查 pid）。
- `pid_map_lookup()` 只在 `PID_MAP_PROBE`(8) 個槽內探測，且有 `PID_MAP_TTL_MS = 3000` 上限，不會無限答錯。

→ 加「新 SYN 清該 port」能把它縮到零，但縮的是次毫秒。**不值得動。**

### 8.7 結論

| 項目 | 原建議 | 實測後 |
| :--- | :--- | :--- |
| P1-1 連線表加 hash index | P1，最大單一效能問題 | **不做** —— O(M) 非 O(N)，現實負載 <2.5% 單核 |
| P1-2 新 SYN 清 pid 快取 | P1，低成本 | **不做** —— 殘餘窗口是次毫秒 |
| （新發現）折疊重複查表 | — | **已實作** —— 省 21–25%（§9.4） |

**負面結果留檔的理由**：防止下一個人（或下一輪的我）再花一輪重新推導「連線表是不是瓶頸」。**它不是。** 若哪天真的需要，槓桿在「折疊重複查表」，不在 hash index。

⚠️ 但 8.2 的**負向擴展**值得記住：若未來有人想靠「調大 `NUM_PACKET_THREADS`」換吞吐，會**拿到更差的結果**。這是陷阱，不是優化點。

---

## 9. 追加性能改動（2026-10-03，已實作並部署）

§8 把連線表判定為「不是瓶頸」之後，繼續沿**封包路徑**找，結果找到了比連線表大一個數量級的東西。

### 9.1 最大的單一發現：每個封包一次多餘的 `SetEvent`（省 ~350 ns/包）

`dispatch_packet()` 每次入列後都呼叫 `SetEvent(q->wake)`：

```c
    if (queued) {
        SetEvent(q->wake);      // 每個封包一次
        return;
    }
```

但 `flow_worker()` 的設計是**一次喚醒排空整個佇列**（原註解自己寫了 "one wait per burst instead of one wait per packet"）。所以 worker 正在忙著排空時，這些 `SetEvent` 全是多餘的 —— 而 `SetEvent` 是**核心轉換**。

新增 `tests/bench_dispatch_wake.c` 量測（1500-byte payload、512 槽，與 `FLOW_QUEUE_SLOTS` 相同）：

| 項目 | 成本 |
| :--- | ---: |
| 原始 `SetEvent`，沒有等待者 | **309.4 ns/op** |
| `SetEvent` + `WaitForSingleObject` 來回 | 624.3 ns/op |
| 完整生產者/消費者迴圈，**每包都 signal**（改動前） | **444.8 ns/pkt** |
| 同上，**只在 idle→busy 轉換時 signal**（改動後） | **95.3 ns/pkt** |
| 節省 | **349.5 ns/pkt（79%）** |

對照：連線表查詢是 78 ns/包。**這個多餘的喚醒是它的 4.5 倍。** 150k pps 時差 5.2% 單核。

**修法**：加一個 `wake_pending` 閘。

```c
// 生產者
if (InterlockedExchange(&q->wake_pending, 1) == 0) SetEvent(q->wake);

// 消費者（順序是關鍵）
InterlockedExchange(&q->wake_pending, 0);                     // 1. 先重新武裝
EnterCriticalSection(&q->lock); idle = (q->count == 0);
LeaveCriticalSection(&q->lock);                               // 2. 再檢查
if (idle) WaitForSingleObject(q->wake, 1000);                 // 3. 才睡
```

⚠️ **順序不能顛倒。** 若「先檢查空、後重設旗標」，中間入列的生產者會看到 `wake_pending == 1` 而跳過 `SetEvent`，封包就卡到 1 秒逾時。先重設再檢查可證明無漏：生產者若因 `pending == 1` 而沒 signal，代表它的**入列**早於消費者的**重設**，也就早於消費者的**檢查** → 檢查必然看到 `count > 0`，於是根本不睡。

**漏喚醒的偵測方式**（這種 bug 的症狀是「偶爾卡 1 秒」，很容易被當雜訊）：量「生產者推完最後一包」到「消費者收完」的**尾延遲**。正常是次毫秒；漏一次訊號就是 ~1000 ms（Wait 逾時）。

```
run                             tail (ms)      verdict
A steady  (signal always)            0.07           ok
B steady  (gated)                    0.07           ok
A bursty  (signal always)            0.07           ok
B bursty  (gated)                    0.10           ok
OVERALL: PASS - no dropped signals in any run
```

（bursty 模式每 2000 包睡 1 ms，刻意製造 idle↔busy 轉換 —— 那正是閘控會出錯的地方。）

### 9.2 pid 解析失敗時會整表快照兩次（省 ~650 µs/次）

`handle_new_connection_logic()` 已經跑完整條解析鏈（結果快取 → 事件 map → `GetExtendedTcpTable`），但解析失敗時它把工作交給 `check_process_rule()`，而後者**又跑一次同樣的鏈**。因為失敗的解析刻意不進快取（`pid_result_cache_store` 開頭 `if (pid == 0) return;`），第二次就是**再一次 ~650 µs 的整表快照**。

修法：`check_process_rule()` 加 `DWORD pid_in, BOOL have_pid`，呼叫端把已解析的結果交下去。`have_pid == TRUE` 時整條解析鏈跳過 —— **包含 `pid == 0` 的情況，那正是重複最貴的時候**。舊行為用 `have_pid = FALSE` 完整保留。

> 語意：同樣輸入、相隔數微秒，第二次查詢不可能給出不同答案。唯一差別是「第一次失敗後第二次剛好成功」這種競態不再被利用 —— 那不是設計行為，是巧合。

### 9.3 兩個看過但**判定不做**的（負面結果）

| 候選 | 為什麼不做 |
| :--- | :--- |
| **DIRECT 快路徑**（上游的 `port_direct_bitmap`）：receiver 直接重送 DIRECT 流，跳過佇列 | 改動後每包約 95 ns，省下的是這個量級。但 `NR_Core.c` 的註解記錄過：當初多執行緒 `WinDivertRecv` 造成 TCP 重排 → 上傳吞吐**腰斬 50%**，flow queue 就是為此存在。DIRECT/PROXY 決策翻轉時會有「已入列 vs 直接送」的混流窗口，正是重排來源。**用 50% 吞吐風險換 ~1% 單核，不划算。** |
| **增量更新 checksum**（RFC 1624）取代 `WinDivertHelperCalcChecksums` | 後者實測 320 ns/包，是改寫路徑上最大的一筆。但增量更新要自己處理 IP header + TCP/UDP pseudo-header（v4/v6 各一套），錯了就是**每個代理封包靜默損壞**。省 ~0.7% 單核，換全域流量正確性風險。**不做。** |

### 9.4 驗證與部署

- **測試**：`run_tests.ps1` 重編譯全部 → **243 項全過**（dns_snoop 29 / filter 32 / lock_stress 1 / rules 24 / state 62 / udp_rewrite 22 / utils 73）。
- ⚠️ **喚醒閘控的驗證只有 `bench_dispatch_wake.c`**（它複製了同一套協定）。**C 測試套件覆蓋不到 `dispatch_packet` / `flow_worker`**，因為它們需要真的 WinDivert handle。說清楚：這項改動的證據是「協定正確性論證 + 尾延遲實測」，**不是**單元測試。
- **部署**：`build.ps1` → 根目錄；再手動同步 `IntegratedApp.dist/`。三份 dll 皆 **240640 B**，標記齊全。
- **改動檔案**：`NR_Core.c`（TCP/UDP 分支折疊、`wake_pending` 閘、`flow_worker` 等待順序）、`NR_RuleEngine.c` / `.h`（`check_process_rule` 新增 `pid_in` / `have_pid`）。

---

## 附錄：上游值得留意的註解（踩坑記錄）

這些是上游程式碼註解裡明講的「我們踩過」：

- `pb_internal.h:30-37`：多封包執行緒會造成 TCP 重排 → 瀏覽器收 3 個 DUPACK → 壅塞視窗減半 → **上傳吞吐腰斬 50%**。改用單一有序執行緒。
- `ProxyBridge.c:981-985`：filter 加 `not impostor` 是為了避免 `WinDivertSend` 重入捕捉迴圈導致「延遲數秒 + DTLS 握手失敗」。（見 §4 對這條的保留意見。）
- `ProxyBridge.c:1036-1048`：`QUEUE_TIME=8` 低於最小值 100，造成持續上傳下大量丟包 → 上傳掉 40–60%。
- `pb_internal.h:67-72`：連線 stale timeout **必須**大於 relay keepalive，否則空閒但正常的連線（IMAP IDLE、語音頻道、WebSocket、DB pool）會被中途回收，表現為「數小時的靜默降級直到重啟」。
- `pb_dns.c:271-275`：不解 DNS flush 的話，規則建立前已解析過的域名永遠沒有 IP→hostname 對照 → domain 規則無法命中。
- `pb_rules.c:398`：`*.example.com` **也匹配** apex `example.com`（Proxifier/Clash 慣例）。本專案 `NR_Utils.c:587-590` 行為相同，一致。
