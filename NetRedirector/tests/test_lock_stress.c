// --- TEST: 多執行緒壓力測試 (鎖拆分無死鎖/無崩潰) ---
#include "test_framework.h"
#include "NR_State.h"
#include "NR_RuleEngine.h"
#include "NR_Utils.h"
#include "NetRedirector.h"

static volatile LONG g_failures = 0;
static volatile LONG g_rounds = 0;

static DWORD WINAPI rule_ops(LPVOID arg)
{
    (void)arg;
    for (int i = 0; i < 1500; i++) {
        UINT32 rid = NetRedirector_AddRule("stress.exe", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY);
        if (rid == 0) { InterlockedIncrement(&g_failures); }
        NetRedirector_EnableRule(rid);
        NetRedirector_DisableRule(rid);
        if (!NetRedirector_DeleteRule(rid)) { InterlockedIncrement(&g_failures); }
        InterlockedIncrement(&g_rounds);
    }
    return 0;
}

static DWORD WINAPI pid_rule_ops(LPVOID arg)
{
    (void)arg;
    DWORD self = GetCurrentProcessId();
    for (int i = 0; i < 1500; i++) {
        UINT32 rid = NetRedirector_AddRuleByPID(self, "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 0);
        if (rid == 0) { InterlockedIncrement(&g_failures); }
        if (!NetRedirector_DeleteRule(rid)) { InterlockedIncrement(&g_failures); }
        InterlockedIncrement(&g_rounds);
    }
    return 0;
}

static DWORD WINAPI proxy_ops(LPVOID arg)
{
    (void)arg;
    for (int i = 0; i < 1500; i++) {
        UINT32 pid = NetRedirector_AddProxyConfig(PROXY_TYPE_SOCKS5, "test", "127.0.0.1", 1080, "u", "p", TRUE);
        if (pid == 0) { InterlockedIncrement(&g_failures); continue; }
        NetRedirector_EditProxyConfig(pid, PROXY_TYPE_HTTP, "test2", "127.0.0.1", 3128, "", "", FALSE);
        NetRedirector_EnableProxyConfig(pid);
        NetRedirector_DisableProxyConfig(pid);
        if (!NetRedirector_DeleteProxyConfig(pid)) { InterlockedIncrement(&g_failures); }
        InterlockedIncrement(&g_rounds);
    }
    return 0;
}

static DWORD WINAPI conn_ops(LPVOID arg)
{
    long base = (long)(LONG_PTR)arg;
    for (int i = 0; i < 1500; i++) {
        // [Fixed] 每執行緒使用不重疊的 port 區段 (base*20000 + 1024 + i):
        // 舊公式 (base*997+i)%20000+1024 會跨執行緒碰撞, 碰撞時
        // 「本執行緒 add → 他執行緒 remove → 本執行緒 is_tracked」
        // 是本質上的競態, 與鎖的正確性無關 (間歇性失敗)。
        // 不重疊區段仍對同一把鎖施壓, 但語意上每個 port 只有一個擁有者。
        UINT16 port = (UINT16)(base * 20000 + 1024 + i);
        UINT8 src[16] = {127, 0, 0, 1};
        UINT8 dst[16] = {8, 8, 8, 8};
        add_connection(port, AF_INET, src, dst, 443, 1, RULE_ACTION_PROXY, FALSE);
        if (!is_connection_tracked(port, AF_INET, dst)) { InterlockedIncrement(&g_failures); }
        remove_connection(port, AF_INET, dst);
        InterlockedIncrement(&g_rounds);
    }
    return 0;
}

static DWORD WINAPI pid_lookup_ops(LPVOID arg)
{
    (void)arg;
    char name[256];
    DWORD self = GetCurrentProcessId();
    for (int i = 0; i < 1500; i++) {
        get_process_name_from_pid(self, name, sizeof(name));
        get_process_id_from_connection(inet_addr("127.0.0.1"), 9999);  // cache miss 路徑
        get_process_id_from_udp_connection(inet_addr("127.0.0.1"), 9998);
        InterlockedIncrement(&g_rounds);
    }
    clear_pid_cache();
    return 0;
}

int main(void)
{
    init_locks();
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[FAIL] WSAStartup\n");
        return 1;
    }

    HANDLE threads[10];
    threads[0] = CreateThread(NULL, 0, rule_ops, NULL, 0, NULL);
    threads[1] = CreateThread(NULL, 0, pid_rule_ops, NULL, 0, NULL);
    threads[2] = CreateThread(NULL, 0, proxy_ops, NULL, 0, NULL);
    threads[3] = CreateThread(NULL, 0, conn_ops, (LPVOID)1, 0, NULL);
    threads[4] = CreateThread(NULL, 0, conn_ops, (LPVOID)2, 0, NULL);
    threads[5] = CreateThread(NULL, 0, conn_ops, (LPVOID)3, 0, NULL);
    threads[6] = CreateThread(NULL, 0, pid_lookup_ops, NULL, 0, NULL);
    threads[7] = CreateThread(NULL, 0, pid_lookup_ops, NULL, 0, NULL);
    threads[8] = CreateThread(NULL, 0, rule_ops, NULL, 0, NULL);
    threads[9] = CreateThread(NULL, 0, proxy_ops, NULL, 0, NULL);

    DWORD wait = WaitForMultipleObjects(10, threads, TRUE, 60000);
    if (wait == WAIT_TIMEOUT) {
        printf("[FAIL] TIMEOUT — possible deadlock\n");
        return 1;
    }
    for (int i = 0; i < 10; i++) CloseHandle(threads[i]);

    g_tests_run++;
    if (g_failures == 0) { printf("  [PASS] 10 threads x 1500 rounds, 0 failures (rounds=%ld)\n", g_rounds); }
    else { g_tests_failed++; printf("  [FAIL] %ld failures (rounds=%ld)\n", g_failures, g_rounds); }

    return test_summary("test_lock_stress");
}
