// --- TEST: NR_State 連線狀態追蹤 + 代理設定 ---
#include "test_framework.h"
#include "NR_State.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

int main(void)
{
    init_locks();

    printf("== add/get/is_tracked/remove connection (TCP, full key) ==\n");
    {
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 dst[16] = {8, 8, 8, 8};
        UINT16 port = 43210;

        CHECK(is_connection_tracked(port, AF_INET, dst) == FALSE, "not tracked initially");
        add_connection(port, AF_INET, src, dst, 443, 7, RULE_ACTION_PROXY, FALSE);
        CHECK(is_connection_tracked(port, AF_INET, dst) == TRUE, "tracked after add");

        int family = 0;
        UINT8 got_dst[16] = {0};
        UINT16 got_dport = 0;
        UINT32 got_pid = 0;
        RuleAction got_action = RULE_ACTION_DIRECT;
        CHECK(get_connection(port, AF_INET, dst, &family, got_dst, &got_dport, &got_pid, &got_action) == TRUE, "get_connection found");
        CHECK(family == AF_INET, "family preserved");
        CHECK(memcmp(got_dst, dst, 4) == 0, "dest addr preserved");
        CHECK(got_dport == 443, "dest port preserved");
        CHECK(got_pid == 7, "proxy id preserved");
        CHECK(got_action == RULE_ACTION_PROXY, "action preserved");

        // 完整 key: 同埠但不同目的地 / 不同 family 必須 miss
        UINT8 other_dst[16] = {1, 1, 1, 1};
        CHECK(is_connection_tracked(port, AF_INET, other_dst) == FALSE, "same port, other dest -> miss");
        CHECK(is_connection_tracked(port, AF_INET6, dst) == FALSE, "family mismatch -> miss");
        CHECK(is_connection_tracked(port, AF_INET, NULL) == FALSE, "NULL key -> miss");

        remove_connection(port, AF_INET, dst);
        CHECK(is_connection_tracked(port, AF_INET, dst) == FALSE, "untracked after keyed remove");
        CHECK(get_connection(port, AF_INET, dst, NULL, NULL, NULL, NULL, NULL) == FALSE, "get after remove -> FALSE");
    }

    printf("== 同埠不同目的地並存 (TCP, 不再互相覆蓋) ==\n");
    {
        UINT8 src[16] = {0};
        UINT8 d1[16] = {1, 1, 1, 1};
        UINT8 d2[16] = {2, 2, 2, 2};
        UINT16 port = 1000;

        add_connection(port, AF_INET, src, d1, 53, 3, RULE_ACTION_DIRECT, FALSE);
        add_connection(port, AF_INET, src, d2, 443, 9, RULE_ACTION_PROXY, FALSE);

        UINT16 dp = 0;
        UINT32 pid = 0;
        RuleAction act = RULE_ACTION_BLOCK;
        CHECK(get_connection(port, AF_INET, d1, NULL, NULL, &dp, &pid, &act) == TRUE, "d1 entry found");
        CHECK(dp == 53 && pid == 3 && act == RULE_ACTION_DIRECT, "d1 keeps its own fields");
        CHECK(get_connection(port, AF_INET, d2, NULL, NULL, &dp, &pid, &act) == TRUE, "d2 entry found");
        CHECK(dp == 443 && pid == 9 && act == RULE_ACTION_PROXY, "d2 keeps its own fields");

        // keyed remove 只移除指定目的地, 兄弟條目存活
        remove_connection(port, AF_INET, d1);
        CHECK(is_connection_tracked(port, AF_INET, d1) == FALSE, "d1 removed");
        CHECK(is_connection_tracked(port, AF_INET, d2) == TRUE, "d2 sibling survives");
        remove_connection(port, AF_INET, d2);
        CHECK(is_connection_tracked(port, AF_INET, d2) == FALSE, "d2 removed");

        // IPv6 條目與同埠 IPv4 條目互不干擾
        UINT8 v6dst[16] = {0x20,0x01,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0,0x01};
        add_connection(port, AF_INET6, src, v6dst, 443, 5, RULE_ACTION_PROXY, FALSE);
        CHECK(is_connection_tracked(port, AF_INET, v6dst) == FALSE, "v6 entry invisible to v4 key");
        CHECK(is_connection_tracked(port, AF_INET6, v6dst) == TRUE, "v6 entry found by v6 key");
        remove_connection(port, AF_INET6, v6dst);
    }

    printf("== [回歸] 舊埠 stale PROXY 條目不得綁架新目的地連線 ==\n");
    {
        // Gpc/CODEX 情境: app 異常關閉 (無 FIN/RST), conntrack 殘留
        // (port -> 舊目的地, PROXY); OS 把同一臨時埠發給新 socket,
        // 新連線要去內網主機。port-only key 下此封包會被誤送進 relay。
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 old_dst[16] = {93, 184, 216, 34};   // 舊外部伺服器
        UINT8 lan_dst[16] = {192, 168, 1, 1};     // 新連線其實要去內網
        UINT16 port = 51234;

        add_connection(port, AF_INET, src, old_dst, 443, 7, RULE_ACTION_PROXY, FALSE);

        CHECK(is_connection_tracked(port, AF_INET, old_dst) == TRUE, "old flow still tracked");
        CHECK(is_connection_tracked(port, AF_INET, lan_dst) == FALSE,
              "new dest NOT hijacked by stale port entry");
        CHECK(get_connection(port, AF_INET, lan_dst, NULL, NULL, NULL, NULL, NULL) == FALSE,
              "new dest lookup misses -> reaches rule/LAN evaluation");

        remove_connection(port, AF_INET, old_dst);
    }

    printf("== UDP 多目的地 (同 socket 送多個伺服器) ==\n");
    {
        UINT8 src[16] = {192, 168, 1, 10};
        UINT8 dns1[16] = {8, 8, 8, 8};
        UINT8 dns2[16] = {1, 1, 1, 1};
        UINT16 port = 53210;

        // 同一個 UDP socket 先後送 8.8.8.8:53 與 1.1.1.1:53 (不同代理)
        add_connection(port, AF_INET, src, dns1, 53, 7, RULE_ACTION_PROXY, TRUE);
        add_connection(port, AF_INET, src, dns2, 53, 8, RULE_ACTION_PROXY, TRUE);

        // 兩個目的地各自追蹤,不互相覆蓋
        CHECK(is_connection_tracked_udp(port, AF_INET, dns1) == TRUE, "dest1 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET, dns2) == TRUE, "dest2 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET, src) == FALSE, "unknown dest not tracked");

        UINT16 dport = 0;
        UINT32 proxy_id = 0;
        UINT8 got_dest[16] = {0};
        CHECK(get_connection_udp(port, AF_INET, dns1, &dport, &proxy_id) == TRUE, "lookup dest1");
        CHECK(proxy_id == 7, "dest1 keeps its own proxy id");
        CHECK(get_connection_udp(port, AF_INET, dns2, &dport, &proxy_id) == TRUE, "lookup dest2");
        CHECK(proxy_id == 8, "dest2 keeps its own proxy id");
        CHECK(get_connection_udp(port, AF_INET6, dns1, &dport, &proxy_id) == FALSE, "family mismatch -> miss");

        // UDP 條目不得被 TCP 查詢/移除路徑誤刪 (同埠 + 同目的地也不行)
        CHECK(is_connection_tracked(port, AF_INET, dns1) == FALSE, "TCP lookup skips UDP entries");
        remove_connection(port, AF_INET, dns1);
        CHECK(is_connection_tracked_udp(port, AF_INET, dns1) == TRUE, "TCP remove keeps UDP entry");

        // 回應改寫用的 per-app-port 查詢: 找得到任一 UDP 條目的目的 port
        CHECK(get_udp_dest_port_for_app(port, &dport) == TRUE, "response rewrite lookup found");
        CHECK(dport == 53, "response rewrite port");
        clear_connections();
        CHECK(get_udp_dest_port_for_app(port, &dport) == FALSE, "cleared -> miss");
    }

    printf("== IPv6 UDP 多目的地 ==\n");
    {
        UINT8 src[16] = {0};
        UINT8 dst6a[16] = {0x20,0x01,0x48,0x60,0,0,0,0,0,0,0,0,0,0,0x88,0x88};  // 2001:4860::8888
        UINT8 dst6b[16] = {0x26,0x02,0x06,0x00,0,0,0,0,0,0,0,0,0,0,0x00,0x10};  // 2606:4700::1110-ish
        UINT16 port = 53211;

        add_connection(port, AF_INET6, src, dst6a, 853, 7, RULE_ACTION_PROXY, TRUE);
        add_connection(port, AF_INET6, src, dst6b, 853, 8, RULE_ACTION_PROXY, TRUE);
        CHECK(is_connection_tracked_udp(port, AF_INET6, dst6a) == TRUE, "v6 dest1 tracked");
        CHECK(is_connection_tracked_udp(port, AF_INET6, dst6b) == TRUE, "v6 dest2 tracked");

        UINT32 proxy_id = 0;
        CHECK(get_connection_udp(port, AF_INET6, dst6a, NULL, &proxy_id) == TRUE, "v6 dest1 lookup");
        CHECK(proxy_id == 7, "v6 dest1 proxy id");
        CHECK(get_connection_udp(port, AF_INET6, dst6b, NULL, &proxy_id) == TRUE, "v6 dest2 lookup");
        CHECK(proxy_id == 8, "v6 dest2 proxy id");
        clear_connections();
    }

    printf("== logged connections ==\n");
    {
        UINT8 dst[4] = {9, 9, 9, 9};
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == FALSE, "not logged initially");
        add_logged_connection(1234, AF_INET, dst, 443, RULE_ACTION_PROXY);
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == TRUE, "logged after add");
        clear_logged_connections();
        CHECK(is_connection_already_logged(1234, AF_INET, dst, 443, RULE_ACTION_PROXY) == FALSE, "cleared");
    }

    printf("== proxy configs (Add/Get/Edit/Delete) ==\n");
    {
        UINT32 pid = NetRedirector_AddProxyConfig(PROXY_TYPE_SOCKS5, "Test", "127.0.0.1", 1080, "u", "p", TRUE);
        CHECK(pid != 0, "AddProxyConfig returns id");
        CHECK(pid == 1, "first proxy id = 1");

        // get_proxy_by_id 契約: 呼叫端須持有 lock_proxies
        EnterCriticalSection(&lock_proxies);
        PROXY_CONFIG *cfg = get_proxy_by_id(pid);
        CHECK(cfg != NULL, "get_proxy_by_id found");
        if (cfg) {
            CHECK(cfg->enabled == TRUE, "enabled flag");
            CHECK(cfg->proxy_port == 1080, "port stored");
            CHECK(strcmp(cfg->proxy_ip, "127.0.0.1") == 0, "ip stored");
        }
        LeaveCriticalSection(&lock_proxies);

        CHECK(NetRedirector_EditProxyConfig(pid, PROXY_TYPE_HTTP, "Test2", "127.0.0.1", 3128, "", "", FALSE) == TRUE, "EditProxyConfig");
        EnterCriticalSection(&lock_proxies);
        cfg = get_proxy_by_id(pid);
        if (cfg) {
            CHECK(cfg->proxy_type == PROXY_TYPE_HTTP, "type updated");
            CHECK(cfg->proxy_port == 3128, "port updated");
            CHECK(cfg->enabled == FALSE, "disabled updated");
        }
        LeaveCriticalSection(&lock_proxies);

        CHECK(NetRedirector_DeleteProxyConfig(pid) == TRUE, "DeleteProxyConfig");
        EnterCriticalSection(&lock_proxies);
        CHECK(get_proxy_by_id(pid) == NULL, "gone after delete");
        LeaveCriticalSection(&lock_proxies);
    }

    return test_summary("test_state");
}
