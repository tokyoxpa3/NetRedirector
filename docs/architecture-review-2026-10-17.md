# NetRedirector 架構與程式碼品質健檢報告

> 日期：2026-10-17　｜　版本基準：`v1.9.1`（`7df5450`）　｜　分析方式：實際跑測試／靜態掃描／讀碼
> **本報告所有數字皆為當日實測**，非引用舊筆記。測試基準：`pytest` **246 passed**。

---

## 一、整體架構

專案是「**C 核心引擎 + Python GUI 殼**」的雙層結構，職責分界很清楚：

```
┌────────────────────────── Python 層（GUI／編排）──────────────────────────┐
│  IntegratedApp.py  MainWindow = 5 個 Tab Mixin 的組裝點                   │
│    ├─ tabs_hub / tabs_rules / tabs_proxies / tabs_monitor / tabs_vpngate  │
│    ├─ NetRedirector.py    ctypes 封裝（唯一 DLL 入口，含能力探測）         │
│    ├─ config_store.py + secure_config.py + autosave.py   設定落地          │
│    └─ control_api.py      127.0.0.1 HTTP 控制介面（供自家工具要求直連）    │
└──────────────────────────────────┬────────────────────────────────────────┘
                     ctypes / callback（log + connection）
┌──────────────────────────────────┴──────────────── C 層（引擎）───────────┐
│  NetRedirector.c   導出 API／生命週期／日誌／防火牆規則                    │
│  NR_Core.c         WinDivert 收包 → 分流佇列 → NAT 改寫 → relay            │
│  NR_RuleEngine.c   規則比對（PID/名稱/hosts/ports/protocol）               │
│  NR_State.c        連線追蹤（CONNECTION_INFO 鏈表 + 關閉寬限期）           │
│  NR_PidMap.c       socket-event PID 快取（4096 槽，TTL 3000ms）            │
│  NR_Utils.c        IP/域名/CIDR 比對、DNS snoop、在地網段偵測              │
│  NR_Protocol.c     SOCKS5／HTTP CONNECT 握手                              │
└───────────────────────────────────────────────────────────────────────────┘
```

**規模**：Python 34 檔 / **12,073 行**；C 16 檔 / **7,678 行**（含 `windivert.h` 630 行）。
測試：Python **3,940 行**、C **3,482 行**。

### 架構上真正的優點（不是客套）

1. **封包熱路徑經過實測優化，且有微基準佐證。** `NR_Core.c` 的 flow-queue 用「slot 緩衝區預配置 + 只在 idle→busy 轉換時 `SetEvent`」，註解明確寫出省下 ~350 ns／包（`bench_dispatch_wake.c` 可重現）。這種「先量再改」的紀律在個人專案裡很少見。
2. **鎖的粒度切分正確且有序。** 從單一 global lock 拆成 `lock_rules / lock_connections / lock_logged / lock_proxies / lock_udp / lock_pid_cache`，並在 `NR_Common.h` 明文寫下「**絕不同時持有兩把鎖**，唯一例外是 UDP relay 可持 `lock_udp` 時短暫取 `lock_connections`（反向永不發生）」。這是有紀錄的 lock ordering。
3. **日誌是可證偽的。** `log_message()` 一路落地到 `NetRedirector.engine.log`（1 MB 輪替、每秒 200 行上限、被折疊的行**會計數並回報**，不靜默丟棄）。而且有 `log_message_throttled()` 帶 16 個具名槽位，讓「每連線觸發一次」的失敗路徑不會把日誌變成第二次故障。
4. **防禦性寫得好。** C 端 `strncpy/snprintf` 全覆蓋（**零** `strcpy/strcat/sprintf`），回家路徑全部檢查 `NULL`；Python 端 `config_store` 有原子寫入（tmp + `fsync` + `os.replace`）、`secure_config` 用 DPAPI 加密密碼、`updater` 有 SHA256 校驗與 zip-slip 防護。
5. **模組化已經起步且做對方向。** `IntegratedApp.py` 從巨石拆出 config/UI/主題/控制 API，`AutoSaveMixin` + `_request_save()` 把「變更即存」抽象成單一入口。

### 現有功能（README 對照實碼，全部確認存在）

| 區塊 | 功能 |
| --- | --- |
| Hub | 多埠監聽（30677–30692）、網卡多對一綁定、依延遲選路＋故障轉移 |
| Rules | 進程名／PID 匹配、hosts（域名/IPv4/IPv6/CIDR）、ports、TCP/UDP/BOTH、Proxy/Direct/Block |
| Proxies | SOCKS5 + HTTP、帳密認證、socks5h 遠端 DNS、批次 Ping 測試 |
| 智慧直連 | 私有網段（含 IPv6 ULA）＋ on-link 動態辨識自動繞過代理 |
| Monitor | 即時流量記錄、右鍵一鍵建規則 |
| VPN Gate | 節點抓取／排序／篩選、SoftEther `vpncmd` 自動設定＋連線＋tunnel 驗證、自動補線、穩定度評分 |
| 更新 | GitHub Release 檢查、多路徑選路下載、SHA256 校驗、背景替換重啟 |
| 控制 API | `127.0.0.1:8767`、token 驗證、`/ping` `/rules` `/ensure-direct` |
| 其他 | 開機自動啟動（工作排程器）、17 國語系、自動存檔＋關機強制落地 |

---

## 二、不足、技術債與風險

### A. 資料一致性與持久化（**最高風險**）

| # | 問題 | 證據 | 後果 |
| --- | --- | --- | --- |
| A1 | **設定還原對 `self.rules` 是 `append` 不是取代**，且 C 端 `AddRuleWithProxy` **無去重**（前插） | `IntegratedApp.py:776`；清空只在 `__init__:167`；`NetRedirector.c:313` | 重複載入／控制 API 搶在 `load_config` 前建規則時，**同一條規則進清單兩次、DLL 也兩條** ⇒ 規則表膨脹、使用者刪不掉「第二條」 |
| A2 | **讀檔 OSError（被鎖）只回 `None` 不動檔** | `config_store.py` `except OSError: return None` | 檔案被防毒／備份軟體鎖住時以**空白設定啟動**，此後第一次存檔**蓋掉好檔** |
| A3 | **`_apply_loaded_config` 整段包在 `except Exception`** | `IntegratedApp.py:796` | 還原中途拋錯 ⇒ **後面所有設定都不還原**（半套狀態） |
| A4 | **`CONFIG_FILE = "config.json"` 是相對路徑** | `IntegratedApp.py:113` | 綁 CWD；從不同工作目錄啟動會讀／寫到別的 `config.json` |

### B. i18n 缺口（功能可見但**靜默**）

- 抽樣 109 個 `tr.t()/self.t()` 的 CJK 字串，**16 個不在 `zh_TW.json`**。
- 新發現（先前筆記只記了 `自動偵測並加入直連程式` 與 ` (自動)` 兩個）：
  `由代理端解析網域 (socks5h)`、`遠端 DNS:`、`確認`、`主網路`、`代理只會部分生效`、
  `節點池是空的，沒有需要重置的資料`、`取得 SeDebugPrivilege 失敗…`、`刪除規則…` 片段等。
- ⚠️ **`tests/test_i18n.py` 抓不到**：它只驗「各語系鍵集合一致／非空／非 CJK 語系值不含中文」，
  **不驗「UI 用了新字串但沒進表」**。缺鍵時 `i18n.t()` 直接回退原文 ⇒ 非中文使用者看到中文。
- VPN Gate 分頁的篩選條件（最低速度、國家、排除 public-\*）**完全沒有進 config**（`config_store.py` 零 vpn 欄位）⇒ 每次啟動都要重設。

### C. 交付品質與版控衛生

| # | 問題 | 證據 |
| --- | --- | --- |
| C1 | **HEAD 與工作區不自洽**：`HEAD:IntegratedApp.py` 的 `control_api` 命中數 = **0**，工作區是 `import control_api`；`control_api.py`、`tests/test_control_api.py`、`tests/test_auto_direct_integration.py` **皆未被 git 追蹤** | `git show HEAD:…`、`git ls-files` |
| C2 | `.gitignore` 漏掉 **`NetRedirector.engine.log`、`.pingtl.txt`、`.workbuddy-ai/`、`.fluent_*`** | `git check-ignore` |
| C3 | 版控仍含第三方二進位 `vcruntime140.dll`(120K)、`WinDivert64.sys`(92K) | `git ls-files` |
| C4 | **專案沒有 flake8 設定檔**，E501 一直用預設 79 字元 | 無 `setup.cfg/.flake8/tox.ini/pyproject.toml` |

### D. 程式碼品質（實測數字）

- **flake8（`*.py` + `tests/*.py`）**：441 E501、114 W293、**86 F401**、44 E701、24 E402、23 E128、22 E302、13 W291、9 E305、8 E261、**7 E722（bare `except:`）**、6 W292、3 W391／E231／E116／E114、1 F841／F541／E306／E117。
- **型別註記率 6.9%**（391 個函式只有 27 個有 `->`），且無 mypy／pyright ⇒ 重構無安全網。
- **7 個 bare `except:`** 分佈於 `NetRedirector.py:317`、`network_utils.py:221,276`、`proxy_core.py:117,251,269,293`。
- 3 個 `demo_*.py`（2,200+ 行）＋ `legacy/`（4 檔）為未追蹤死碼。

### E. 測試覆蓋不均

- **零測試**：`ui_theme.py`(558 行)、`app_icon.py`、`single_instance.py`。
- **C 測試 298 項但約 17 分鐘**；`run_tests.ps1` 依賴 `vcvars64.bat` → `reg.exe`，在多數受限環境**跑不動**，而 CI 直接呼叫它 ⇒ **CI 綠燈與本機可驗證性不一致**。
- ⚠️ 測試用 `cl` **沒有 `/utf-8`**（只有 `build.ps1` 有）⇒ 測試編譯的字碼頁與出貨建置**不同**。

### F. 安全與供應鏈

- 更新包 **zip 與 SHA256SUMS 同源**（同一 GitHub Release）⇒ 校驗只防傳輸損毀，**不防上游／帳號被竄改**；無 detached signature、無程式碼簽章（README 自己也提到 SmartScreen 誤報）。
- C 端 `run_netsh_firewall()` 以 `CreateProcessA` 呼叫 `netsh.exe`，命令字串由 `snprintf` 組出（埠號與名稱皆為內部產生，目前無注入面），但這是**唯一**的外部命令呼叫點，值得標記為需持續審視的邊界。

### G. 功能缺口（沿用未做清單，本次已複查成立）

- **IPv4 CIDR `10.0.0.0/8` 仍是「靜默永不匹配」陷阱**（IPv4 分支無 `/` 早退 ⇒ 被當域名解析）。
- `g_dns_via_proxy` 與 `g_unknown_process_action` **無 UI 介面**（都是 C 預設值，使用者無法調）。
- P2-2 可選「代理 localhost」、P2-3 規則顯式排序、P2-4 規則匯入匯出：未動。
- **MSD 同步缺口**：`/d/workspace/MultiSocksDownloader/updater.py:560` 的 `_rank_download_paths(url, use_proxy=True)` **仍無 `log_cb`** ⇒ D5/D6 未移植。

---

## 三、改善方向（依優先序）

> 效益／影響範圍以「**使用者可感知** 或 **阻擋後續工作**」為排序依據。每項都標了驗證方式，因為這個專案最大的風險向來不是「改錯」，而是**「改完不知道有沒有真的生效」**。

### 🔴 P0 — 立即處理（資料遺失／無法交付）

#### P0-1 修復「規則重複還原」與去重
- **做什麼**：`_apply_loaded_config()` 開頭改為**取代**而非 append（或明確在載入前 `self.rules.clear()`，並讓 `load_config` 與 `_scan_auto_direct_targets` 有明確先後）；同時在 C 端 `AddRuleWithProxy` 加入以 `(process_name, target_pid, hosts, ports, protocol, action, proxy_id)` 為鍵的去重。
- **預期效益**：消除規則表重複與「刪不掉的第二條」；避免重複規則造成 `match_rule()` 線性掃描變慢。
- **影響範圍**：`IntegratedApp.py`、`NetRedirector.c`、`NR_RuleEngine.c`。**需重建 DLL**（`IntegratedApp.dist/` 是打包版，Python 改動也要重建）。
- **驗證**：`pytest`（246 基準不降）＋ C 測試（298 基準）＋ 新增回歸測試「連續載入兩次，規則數不變」。

#### P0-2 讓工作區與 HEAD 自洽，恢復「隨時可交付」
- **做什麼**：把 `control_api.py`、`tests/test_control_api.py`、`tests/test_auto_direct_integration.py`、`config_store.py`、`tests/test_config_store.py`、`IntegratedApp.py` 一起提交為**單一邏輯變更**（本機控制 API 功能）；`.pingtl.txt`、`engine.log`、`.fluent_*`、`.workbuddy-ai/` 進 `.gitignore`。
- **預期效益**：任何人 clone 都能跑；避免未來「只提交一半」造成 ImportError。
- **影響範圍**：僅 git 操作與 `.gitignore`。⚠️ **不要 `git add -A`**（會誤收 `config.json`、`vpn_history.json` 之外的執行期產物與 demo 檔）。
- **驗證**：`git status` 乾淨；在暫存 clone 中跑 `pytest`。

#### P0-3 修掉 `config.json` 讀取被鎖時的「蓋好檔」窗口
- **做什麼**：`load_config_file()` 的 `except OSError` 不再與「檔案不存在」共用 `None`；改為回傳可區分的狀態（例如 `LoadResult(ok=False, locked=True)`），呼叫端在 locked 時**以唯讀模式啟動並禁止本次存檔**（或延後到解鎖），並至少發一筆可見警告。
- **預期效益**：消除「設定無聲消失」這一類最難回報的故障。
- **影響範圍**：`config_store.py`、`IntegratedApp.py`、`tests/test_config_store.py`。
- **驗證**：新增測試模擬 `PermissionError`，斷言**不改檔**、**不排程存檔**。

### 🟠 P1 — 高價值（品質可見度／可維護性）

#### P1-4 修補 i18n 缺口並補上「缺鍵偵測」
- **做什麼**：把 16 個缺鍵補進 17 個語系檔（或至少 zh_TW/zh_CN/en_US）；並在 `tests/test_i18n.py` 新增**反向掃描**：用 AST 抓出所有 `tr.t()`/`self.t()` 的字串常值，斷言每一個都存在於 `zh_TW.json`。
- **預期效益**：非中文使用者不再看到中文；**這類缺陷以後由測試自動擋下**，不再依賴人工複查。
- **影響範圍**：`locale/*.json`、`tests/test_i18n.py`。純資料＋測試，風險極低。
- **驗證**：新測試在修補前**必須紅**、修補後轉綠（先證明它能抓）。

#### P1-5 建立品質門檻（flake8 設定 ＋ 型別檢查起步）
- **做什麼**：新增 `setup.cfg`／`.flake8`，把 `max-line-length` 設為專案實際風格（例如 100），`extend-ignore` 明確列出接受項；把 **E722（bare except）、F821/F811、F841** 升級為**必須為零**，E501/W293 允許存量但禁止新增。`NetRedirector.py` 補 `# type: ignore` 起點或對公開 wrapper 加註記。
- **預期效益**：flake8 淨變化=0 的規則**從口頭約定變成可執行檢查**；bare except 這類會吞掉真實錯誤的寫法被擋下。
- **影響範圍**：新增設定檔 + `proxy_core.py`/`network_utils.py`/`NetRedirector.py` 的 7 處 `except:` 改為具名例外。
- **驗證**：`flake8 --statistics` 前後差異符合預期；CI 加入 `--select=E722,F821,F811,F841` 且要求 0。

#### P1-6 讓 C 測試可在受限環境與 CI 中穩定執行
- **做什麼**：把 `run_tests.ps1` 從「依賴 `vcvars64.bat`」改為與 `.workbuddy-ai/.run_ctests2.sh` 相同的手動 `INCLUDE/LIB/PATH` 注入；測試編譯加上 `/utf-8`（與 `build.ps1` 一致）；對測試 EXE 加逾時（已知 `lock_stress`/`logging`/`state`/`udp_rewrite` 印完 summary **不結束**）。
- **預期效益**：CI 與本機驗證結果一致；17 分鐘的測試不再因「卡死」多等，且能進 pre-commit。
- **影響範圍**：`NetRedirector/tests/run_tests.ps1`、`.github/workflows/build.yml`。
- **驗證**：在乾淨環境跑 `run_tests.ps1` 得 298 項、總時長明顯下降。

### 🟡 P2 — 值得做（使用者價值／功能缺口）

#### P2-7 補齊 IP 比對陷阱
- **做什麼**：修 **IPv4 CIDR**（`is_ip_like_pattern()` 對 `10.0.0.0/8` 回 FALSE ⇒ 當域名解析 ⇒ 永不匹配），並新增 IPv4/IPv6 **範圍**表示法（`10.0.0.1-10.0.0.50`）。格式錯誤一律 FALSE、**不落字串比對**。
- **預期效益**：關掉一個「打了規則、沒有錯誤、也永遠不生效」的靜默陷阱（與 v1.9.1 修的 IPv6 CIDR 是同一類問題）。
- **影響範圍**：`NR_Utils.c`、`NR_RuleEngine.c`、提示文字、測試。**需重建 DLL ＋ 端到端驗證**（用可路由位址，勿用 `2001:db8::/32` 文件保留區）。
- **驗證**：C 測試新增案例；實機 A/B（新舊 DLL 交錯）確認流量真的改道。

#### P2-8 把 `g_dns_via_proxy` 與 `g_unknown_process_action` 接上 UI
- **做什麼**：在 ⚙ 選單加兩個選項（DNS 是否走代理／未歸因流量處置），呼叫既有 `SetDnsViaProxy`／`SetUnknownProcessAction`，並持久化。
- **預期效益**：使用者目前**無法**調整這兩個直接影響「DNS 是否外洩」的開關 —— 這是隱私相關的最高價值缺口。
- **影響範圍**：`IntegratedApp.py`、`config_store.py`、locale 檔、測試。
- **驗證**：`pytest` 新增 roundtrip 測試；手動確認開關改變引擎行為（看日誌分支）。

#### P2-9 VPN Gate 篩選條件持久化
- **做什麼**：把最低速度、國家多選、排除 `public-*`／port 443 寫入 config。
- **預期效益**：消除「每次啟動重設」的重複操作。
- **影響範圍**：`tabs_vpngate.py`、`config_store.py`、測試。

### 🟢 P3 — 中長期

| # | 項目 | 說明 |
| --- | --- | --- |
| P3-10 | **更新供應鏈加固** | 為 release 加 detached signature（或改用簽章過的更新來源），並評估 Authenticode 程式碼簽章；至少把 SHA256SUMS 改成由 CI 以獨立金鑰簽署。 |
| P3-11 | **`.gitignore` + 死碼清理** | 忽略 `engine.log`/`.pingtl.txt`/`.fluent_*`/`.workbuddy-ai/`；決定 `demo_*.py`（2,200 行）與 `legacy/` 是保留為文件還是移除。 |
| P3-12 | **測試覆蓋補洞** | `ui_theme`(558 行)、`app_icon`、`single_instance` 目前零測試；`ui_theme` 可用離屏（`QT_QPA_PLATFORM=offscreen` ＋ 必要時 `QT_QPA_FONTDIR`）驗證 QSS/palette 不拋錯。 |
| P3-13 | **移植 D5/D6 到 MSD** | `MultiSocksDownloader/updater.py:560` 補 `log_cb`；改完兩邊都要 grep 驗證（曾誤把文件敘述當程式現況）。 |
| P3-14 | **P2-2/P2-3/P2-4** | 可選代理 localhost、規則顯式排序、規則匯入匯出。規則排序目前是「前插 + 首命中」，語意隱含在插入順序裡，對使用者不可控。 |

---

## 四、建議執行順序（一頁摘要）

| 順序 | 項目 | 為何現在做 | 規模 |
| --- | --- | --- | --- |
| 1 | **P0-2 提交自洽** | 不做的話，後面任何改動都建立在無法交付的基礎上 | 小 |
| 2 | **P0-1 規則去重** | 資料一致性缺陷，會隨控制 API 使用頻率放大 | 中（含 DLL 重建） |
| 3 | **P0-3 讀檔鎖定** | 消除最難回報的「設定無聲消失」 | 小 |
| 4 | **P1-4 i18n** | 低風險、高可見度，且**順手把偵測自動化** | 小 |
| 5 | **P1-5 品質門檻** | 是後面所有重構的安全網 | 小 |
| 6 | **P1-6 C 測試可攜** | 沒有它，P2-7 的驗證會很痛 | 中 |
| 7 | **P2-7 IPv4 CIDR** | 關掉靜默陷阱，與 v1.9.1 同一類問題 | 中 |
| 8 | **P2-8 / P2-9** | 使用者可感知的功能補齊 | 小～中 |

> **共通原則**：本專案歷史上最大的坑不是「改錯程式」，而是**「改完之後靜默地量到錯的結論」**。因此每一項都應附上可執行的驗證步驟（測試或實機 A/B），並優先做「先讓測試變紅、再修到綠」的順序。

---

## 五、附錄：本次實測指令與基準

```bash
# Python 測試（唯一有 pytest 的環境是 .venv）
.venv/Scripts/python.exe -m pytest -q            # → 246 passed in 24.53s

# 靜態掃描
.venv/Scripts/python.exe -m flake8 --count --statistics *.py tests/*.py

# 行數
wc -l *.py ; wc -l NetRedirector/*.c NetRedirector/*.h

# 自洽性
git show HEAD:IntegratedApp.py | grep -c control_api   # → 0（工作區為 1）
git ls-files | grep -c control_api                     # → 0（未追蹤）

# C 測試（受限環境需繞過 vcvars64.bat）
bash .workbuddy-ai/.run_ctests2.sh                     # → 298 項，約 17 分鐘
```
