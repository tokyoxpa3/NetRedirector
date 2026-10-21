// --- TEST: UDP association 回程靜默偵測 ---
//
// 背景：SOCKS5 UDP ASSOCIATE 的 relay 埠會隨代理端的 NAT 映射靜默失效。
// TCP 控制連線靠 keepalive 還活著，sendto 也不會失敗（UDP 無連接），所以
// 「送了卻沒回」是唯一可觀測的訊號。udp_assoc_is_silent() 就是那個判據。
//
// 這裡只驗證純函式的門檻與邊界，不涉及 socket。
#include "test_framework.h"
#include "NR_Core.h"

static UDP_ASSOCIATION make(DWORD last_rx, UINT32 tx, BOOL rx_seen)
{
    UDP_ASSOCIATION a;
    memset(&a, 0, sizeof(a));
    a.last_rx = last_rx;
    a.tx_since_rx = tx;
    a.rx_seen = rx_seen;
    return a;
}

int main(void)
{
    init_locks();

    printf("== NULL 安全 ==\n");
    {
        CHECK(udp_assoc_is_silent(NULL, 1000) == FALSE, "NULL -> FALSE");
    }

    printf("== 從未收到回程（單向流量，寬鬆門檻）==\n");
    {
        UDP_ASSOCIATION a = make(0, 0, FALSE);
        CHECK(udp_assoc_is_silent(&a, 0) == FALSE, "剛建立 -> FALSE");

        a = make(0, 199, FALSE);
        CHECK(udp_assoc_is_silent(&a, 61000) == FALSE,
              "199 個 datagram / 61s -> FALSE（未達 200）");

        a = make(0, 200, FALSE);
        CHECK(udp_assoc_is_silent(&a, 60000) == FALSE,
              "200 個 / 正好 60s -> FALSE（必須超過）");

        a = make(0, 200, FALSE);
        CHECK(udp_assoc_is_silent(&a, 60001) == TRUE,
              "200 個 / 60.001s -> TRUE");

        a = make(0, 500, FALSE);
        CHECK(udp_assoc_is_silent(&a, 10000) == FALSE,
              "500 個但只過 10s -> FALSE（時間未到）");
    }

    printf("== 曾經收到回程（雙向流量，嚴格門檻）==\n");
    {
        UDP_ASSOCIATION a = make(0, 19, TRUE);
        CHECK(udp_assoc_is_silent(&a, 20000) == FALSE,
              "19 個 / 20s -> FALSE（未達 20）");

        a = make(0, 20, TRUE);
        CHECK(udp_assoc_is_silent(&a, 15000) == FALSE,
              "20 個 / 正好 15s -> FALSE（必須超過）");

        a = make(0, 20, TRUE);
        CHECK(udp_assoc_is_silent(&a, 15001) == TRUE,
              "20 個 / 15.001s -> TRUE");

        a = make(0, 100, TRUE);
        CHECK(udp_assoc_is_silent(&a, 1000) == FALSE,
              "100 個但剛收到回程 -> FALSE");

        // 有回程歷史的 association 不會掉到寬鬆門檻
        a = make(0, 150, TRUE);
        CHECK(udp_assoc_is_silent(&a, 40000) == TRUE,
              "150 個 / 40s -> TRUE（雙向流量用嚴格門檻）");
    }

    printf("== GetTickCount 環繞 ==\n");
    {
        // now 比 last_rx 小 = 計數器繞回；無號相減仍是正確的經過時間。
        UDP_ASSOCIATION a = make(0xFFFFFF00u, 20, TRUE);
        CHECK(udp_assoc_is_silent(&a, 0x00000100u) == FALSE,
              "繞回後僅經過 512ms -> FALSE");

        a = make(0xFFFF0000u, 20, TRUE);
        CHECK(udp_assoc_is_silent(&a, 0x00001000u) == TRUE,
              "繞回後經過 0x11000 ms (約 69.6s) -> TRUE");
    }

    return test_summary("test_udp_assoc_liveness");
}
