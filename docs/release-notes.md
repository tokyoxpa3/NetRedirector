# NetRedirector v2.0.0

## hub 正式支援 SOCKS5 UDP，以及一次「看起來能用、其實沒走 VPN」的修正

這一版只動一個檔案：`proxy_core.py`（內建 hub 的 SOCKS5 伺服器）。但它補上的是
協定層缺掉的半邊 —— **過去 hub 只會處理 TCP CONNECT，任何 UDP 請求一律回
0x07（不支援的指令）**。症狀是「把全域流量導向 hub 端口時，DNS、STUN 全部
timeout」，非常容易誤判成「VPN 或網路封了 UDP」。

> ⚠️ **先講最重要的一句：這不是 VPNGate 語音問題的修復。**
> 11-11 的實機對照已確認，**VPNGate 伺服器不轉發隧道內發往外網的 UDP**。
> 本版讓 hub 能正確處理 UDP，但上游不放行時，Discord RTC 仍然不通。
> 詳見底下「已知限制」一節 —— 那是上游政策，客戶端做什麼都救不了。

---

## 一、hub 補上 SOCKS5 UDP ASSOCIATE（CMD 0x03）

### 症狀

把全局流量導向本機 hub 端口（30678，出口綁 VPNGate 虛擬網卡）時，**所有 UDP
（DNS、STUN）全部 timeout**。TCP 正常，所以直覺會往「VPN 封 UDP」或「SoftEther
的 UDP Acceleration 沒開」去查。

### 根因：不是網路，是 hub 不認識這個指令

NR 核心早就支援 UDP：`NR_Common.h` 的 relay 監聽 33200，`NR_Core.c` 的
`establish_udp_associate_with_config()` 會對代理發出 0x03。但 hub 端只定義了
`CMD_CONNECT = 0x01`，`cmd != 0x01` 就直接回 0x07 ⇒ UDP 全滅。

VPNGate 本身沒問題：`ping -S 10.211.1.67 8.8.8.8` 走隧道 45ms 正常；
SoftEther 虛擬網卡是 L3，隧道內本來就能承載 UDP（UDP over TCP），
UDP Acceleration 停用不影響。

### 修正

新增 0x03 分支：`handle_udp_associate()` 挑出口介面 → 建立 UDP socket →
回覆 BND.ADDR / BND.PORT → 在 TCP 控制連線存活期間雙向搬運 datagram。
`cmd` 不是 0x01 / 0x03 時仍然回 0x07，**既有行為完全不變**。

同時補齊 RFC 1928 §7 的標頭處理：

| ATYP | 處理 |
| :--- | :--- |
| `0x01` IPv4 | 直接解出位址 |
| `0x03` 域名 | `idna` 解碼後解析成 IPv4（出口 socket 是 `AF_INET`） |
| `0x04` IPv6 | 另開 `AF_INET6` socket 原生送出 |
| `FRAG != 0` | 不支援分片，直接丟棄 |

回程標頭也必須同時支援 IPv4 與 IPv6：引擎端對 IPv6 用的是 **22 bytes**
（4 + 16 + 2），若這裡只會組 IPv4，IPv6 的回程會被引擎丟掉。

---

## 二、出口 socket 必須綁到 VPN 網卡 IP（最危險的靜默錯誤）

這是整包改動裡最關鍵的一點，也是最不容易被發現的。

機器上有 16 張 VPN 虛擬網卡（metric 10）與一張實體網卡（metric 1），
**預設路由走實體網卡**。hub 的 TCP 之所以能走 VPN，是靠既有的
`remote.bind((bind_ip, 0))` 明確指定來源。

UDP 若照抄「建 socket 就送」，`sendto()` 會依路由表挑來源位址 ⇒ 封包從
**真實 IP** 出去。結果是「hub 看起來能用 UDP」但實際上完全沒走 VPN ——
比直接失敗更糟，因為沒有任何錯誤訊息，也不會有人去查來源位址。

實測依據：`ping -S 10.211.1.67 8.8.8.8` 45ms（隧道內），
`ping -S 192.168.1.200 8.8.8.8` 6ms（實體網卡），兩條路徑確實不同。
現在 UDP 出口 socket 一律 `bind((bind_ip, 0))`，與 TCP 對齊。

---

## 三、客戶端／出口 socket 分離，不再用「第一個來源」猜人

舊設計用單一 socket 同時收兩邊，再用「第一次收到的來源位址」判斷誰是客戶端。
只要第一個封包判斷錯，整個 session 就會把客戶端送來的封包當成目標回應、
原樣彈回去。而且**不能比對控制連線的 peer IP** —— 引擎的 relay socket 可能
綁在 VPN IP 上，來源會是 `10.211.1.x`。

現在分工明確：

- `client_sock` 只會收到客戶端送來的 SOCKS5 UDP 封包；
- `out_sock`（綁在 VPN 網卡上）只會收到目標回來的原始封包；
- IPv6 目標另開 `out6_sock`，不混進 VPN 出口的存活判定。

拆開之後不可能搞錯方向。控制連線關閉或閒置 120 秒時，
`finally` 一定歸還介面配額並關閉所有 socket。

---

## 四、UDP 出口熱切換：用「沉默」當判據

VPNGate 的免費節點隨時會斷，但 UDP 沒有重傳、沒有 RST、也沒有 FIN，
唯一觀察得到的訊號就是**送出去卻完全沒有回應**。

| 參數 | 值 | 理由 |
| :--- | :--- | :--- |
| 觸發 | 送出 ≥ 2 個封包且沉默 ≥ 4 秒 | 兼顧語音與握手兩種節奏 |
| 切換上限 | 4 次 | 目標本來就不回時，不要無限換卡 |
| 切換後冷卻 | 6 秒 | 避免同一輪反覆重試 |
| socket buffer | 1 MB | 吸收語音／遊戲的突發封包 |
| 閒置逾時 | 120 秒 | 回收殭屍 session 的介面配額 |

門檻刻意**用「時間」為主、封包數為輔**，而不是像引擎那樣等 20 個封包：
語音是 50pps，20 個封包只花 0.4 秒；但 Discord 的握手探測是「8 秒才一顆」，
等 20 顆要 160 秒 —— 使用者感受到的就是「retry 好幾次才連上」。

換卡時 `client_sock` 與 BND.PORT 完全不變，**客戶端（引擎）不會察覺**，
只會感覺到一次短暫停頓。若交給引擎判斷，它要等 15 秒才放棄並重撥整個
association，主觀感受就是「連線一直斷」。

---

## 五、連線時間預算：最壞 80 秒 → 8 秒

原本是「每張網卡 5 秒、最多 16 張」＝最壞 **80 秒**。但引擎端等不到
SOCKS5 回應就會記一筆 `SOCKS5 handshake failed` 並丟掉連線，
使用者感受到的是**隨機斷線**。

現在改成兩層預算：單次嘗試 3 秒、整個請求 8 秒。
寧可早點回 `0x01` 讓引擎重試，也不要拖到對方先放棄。

---

## 六、UDP 改挑延遲最低的介面，TCP 維持原策略

TCP 仍用「活躍連線數最少」的負載平衡，避免單一網卡被吃滿。
UDP 沒有重傳，RTT 抖動會直接變成語音斷續，所以新增 `prefer_latency`，
改以**延遲最低**優先、連線數次之。這只影響 UDP，不改 TCP 的行為。

---

## ⚠️ 已知限制：VPNGate 出口的外網 UDP 仍然不通

重新建置後，hub 的 UDP ASSOCIATE 確實生效：`Get-NetUDPEndpoint` 看到
`IntegratedApp` 建立了 `10.211.1.10:62876`（綁在 VPN 網卡上）。
**但 Discord RTC / STUN 仍然是 0/4。**

同一時間、同一台機器的四組對照：

| 測試 | 結果 |
| :--- | :--- |
| `ping -S 10.211.1.10 8.8.8.8`（ICMP 經 VPN） | **OK 112ms** |
| `Resolve-DnsName -Server 10.211.254.254`（UDP 53 到 VPN 內部 DNS） | **OK** |
| Python 綁 VPN IP → UDP 53 / 3478 到外網 | **timeout** |
| 同上再加 `IP_UNICAST_IF` 強制介面 | **timeout** |
| 手機 Pro 出口的 STUN 19302 / 3478 | **OK** |

隧道本身沒問題（ICMP 通、VPN 內部 UDP 通），**只有「隧道內發往外網的 UDP」
被丟棄** ⇒ 是 VPNGate 伺服器的政策，不是 NR、也不是 hub 的實作。

所以：

- hub 的 UDP 支援對**支援 UDP 的上游**仍然有效（手機 Pro 出口已驗證 0x03 可用）；
- 若要用 VPNGate 跑 RTC，只能換節點試（多數應該一樣），或改用支援 UDP 的
  VPN 協定（WireGuard / OpenVPN-UDP）。

---

## 測試

- **`pytest` 246 passed**（與 v1.9.1 基準一致）。
- **`flake8` 淨變化 0**：以違規行內容做多重集合差集、不比行號；
  這次新改動引入的 20 項全數修掉，並順帶消除 3 個既有違規。
- CI 的 `F821` 未定義名稱檢查乾淨、模組匯入 smoke test 通過。
- **loopback 端到端**（11-11）：ASSOCIATE 回覆 `rep=0x00`、BND 位址正確、
  雙向 echo 正確、控制連線關閉後 session 釋放；TCP 迴歸的 CONNECT 正常，
  BIND（0x02）仍回 0x07。
- **C 核心這次未改動**（`NetRedirector/` 一行未改），C 測試由 CI 執行。

## 升級方式

使用內建自動更新即可。版本號從 1.9.1 跳到 **2.0.0**，更新檢查用數值
tuple 比較版本（不是字串比對），不會誤判新舊。

若更新流程本身有問題，直接下載本頁 zip 手動覆蓋
（`NetRedirector.dll` 必須與執行檔同目錄）。

> 提醒：設定檔 `config.json` 放在程式目錄。**手動換版本時請不要把整個資料夾
> 直接刪掉重解壓**，否則設定會跟著消失；內建自動更新會自動保留它。
> 另外，若你跑的是打包版，只替換 `.py` 原始檔**不會生效**，請用釋出的 zip
> 覆蓋（或自行重新建置）。
