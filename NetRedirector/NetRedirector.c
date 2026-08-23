// --- START OF FILE NetRedirector.c ---
#define WIN32_LEAN_AND_MEAN
#include "NR_Common.h"
#include "NetRedirector.h"
#include "NR_Utils.h"
#include "NR_State.h"
#include "NR_Core.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"

// Forward Declarations to prevent implicit declaration warnings
NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id);
static void signal_dns_refresh(void);   // [Added] wake the background DNS refresher (defined above NetRedirector_Start)

// === Global Variable Definitions ===
// Per-structure locks (see NR_Common.h for the ordering rule).
CRITICAL_SECTION lock_rules;
CRITICAL_SECTION lock_connections;
CRITICAL_SECTION lock_logged;
CRITICAL_SECTION lock_proxies;
CRITICAL_SECTION lock_udp;
CRITICAL_SECTION lock_pid_cache;

BOOL running = FALSE;
DWORD g_current_process_id = 0;
HANDLE g_stop_event = NULL;   // manual-reset; wakes sleeping worker threads on Stop

char g_proxy_ip[64] = "";
UINT16 g_proxy_port = 0;
UINT16 g_local_relay_port = LOCAL_PROXY_PORT;
ProxyType g_proxy_type = PROXY_TYPE_SOCKS5;
char g_proxy_username[256] = "";
char g_proxy_password[256] = "";

BOOL g_dns_via_proxy = TRUE;
RuleAction g_unknown_process_action = RULE_ACTION_DIRECT;

LogCallback g_log_callback = NULL;
ConnectionCallback g_connection_callback = NULL;

// Helper to log messages
void log_message(const char *msg, ...)
{
    if (g_log_callback == NULL) return;
    char buffer[1024];
    va_list args;
    va_start(args, msg);
    vsnprintf(buffer, sizeof(buffer), msg, args);
    va_end(args);
    g_log_callback(buffer);
}

// === API Implementations ===

NETREDIRECTOR_API UINT32 NetRedirector_AddRule(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    return NetRedirector_AddRuleWithProxy(process_name, target_hosts, target_ports, protocol, action, 0);
}

NETREDIRECTOR_API UINT32 NetRedirector_AddRuleWithProxy(const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    if (!process_name || !process_name[0]) return 0;
    
    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (!rule) return 0;
    // [Fixed] 清空結構: 名稱規則的 target_pid 必須為 0, 否則 match_rule 會把它當成
    // PID 規則而跳過名稱比對 -> 規則永不匹配, 流量全部走 DIRECT (重大 bug)
    memset(rule, 0, sizeof(PROCESS_RULE));

    rule->rule_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_rule_id);  // [Fixed] 原子遞增, 避免多執行緒拿到相同 ID
    strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
    rule->process_name[MAX_PROCESS_NAME - 1] = '\0';
    rule->protocol = protocol;
    rule->action = action;
    rule->proxy_id = proxy_id;
    rule->enabled = TRUE;

    // Handle Hosts
    if (target_hosts && target_hosts[0]) rule->target_hosts = _strdup(target_hosts);
    else rule->target_hosts = _strdup("*");

    // Handle Ports
    if (target_ports && target_ports[0]) rule->target_ports = _strdup(target_ports);
    else rule->target_ports = _strdup("*");

    EnterCriticalSection(&lock_rules); // Optional if single thread config, but safer
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_rules);

    signal_dns_refresh();   // [Added] resolve domain patterns in target_hosts right away
    return rule->rule_id;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddRuleByPID(DWORD pid, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    PROCESS_RULE *rule = (PROCESS_RULE *)malloc(sizeof(PROCESS_RULE));
    if (!rule) return 0;
    memset(rule, 0, sizeof(PROCESS_RULE));  // [Fixed] 清空結構, 避免未初始化欄位

    rule->rule_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_rule_id);  // [Fixed] 原子遞增, 避免多執行緒拿到相同 ID
    rule->target_pid = pid;      // Set PID
    rule->process_name[0] = '\0'; // Name empty for PID-based rules
    rule->protocol = protocol;
    rule->action = action;
    rule->proxy_id = proxy_id;
    rule->enabled = TRUE;

    // Handle Hosts
    if (target_hosts && target_hosts[0]) rule->target_hosts = _strdup(target_hosts);
    else rule->target_hosts = _strdup("*");

    // Handle Ports
    if (target_ports && target_ports[0]) rule->target_ports = _strdup(target_ports);
    else rule->target_ports = _strdup("*");

    EnterCriticalSection(&lock_rules);
    rule->next = rules_list;
    rules_list = rule;
    LeaveCriticalSection(&lock_rules);

    signal_dns_refresh();   // [Added] resolve domain patterns in target_hosts right away
    return rule->rule_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) { rule->enabled = TRUE; found = TRUE; break; }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    if (found) signal_dns_refresh();   // [Added] re-enabled domain rule may need a fresh resolve
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) { rule->enabled = FALSE; found = TRUE; break; }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteRule(UINT32 rule_id)
{
    if (rule_id == 0) return FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *prev = NULL;
    BOOL found = FALSE;

    while (rule) {
        if (rule->rule_id == rule_id) {
            if (prev) prev->next = rule->next;
            else rules_list = rule->next;
            free(rule->target_hosts);
            free(rule->target_ports);
            free(rule);
            log_message("Deleted rule ID: %u", rule_id);
            found = TRUE;
            break;
        }
        prev = rule;
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    return found;
}

NETREDIRECTOR_API BOOL NetRedirector_EditRule(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action)
{
    return NetRedirector_EditRuleWithProxy(rule_id, process_name, target_hosts, target_ports, protocol, action, 0);
}

NETREDIRECTOR_API BOOL NetRedirector_EditRuleWithProxy(UINT32 rule_id, const char* process_name, const char* target_hosts, const char* target_ports, RuleProtocol protocol, RuleAction action, UINT32 proxy_id)
{
    if (rule_id == 0 || !process_name) return FALSE;
    BOOL found = FALSE;
    EnterCriticalSection(&lock_rules);
    PROCESS_RULE *rule = rules_list;
    while (rule) {
        if (rule->rule_id == rule_id) {
            strncpy(rule->process_name, process_name, MAX_PROCESS_NAME - 1);
            rule->process_name[MAX_PROCESS_NAME-1] = '\0';
            
            if (rule->target_hosts) free(rule->target_hosts);
            rule->target_hosts = _strdup(target_hosts ? target_hosts : "*");

            if (rule->target_ports) free(rule->target_ports);
            rule->target_ports = _strdup(target_ports ? target_ports : "*");

            rule->protocol = protocol;
            rule->action = action;
            rule->proxy_id = proxy_id;
            log_message("Updated rule ID: %u", rule_id);
            found = TRUE;
            break;
        }
        rule = rule->next;
    }
    LeaveCriticalSection(&lock_rules);
    if (found) signal_dns_refresh();   // [Added] hosts may have changed to new domains
    return found;
}

// === Proxy Config APIs ===

NETREDIRECTOR_API BOOL NetRedirector_SetProxyConfig(ProxyType type, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return FALSE;
    if (resolve_hostname(proxy_ip) == 0) return FALSE;

    EnterCriticalSection(&lock_proxies);
    strncpy(g_proxy_ip, proxy_ip, sizeof(g_proxy_ip)-1);
    g_proxy_ip[sizeof(g_proxy_ip)-1] = '\0';   // always null-terminate
    g_proxy_port = proxy_port;
    g_proxy_type = type;
    
    if (username) strncpy(g_proxy_username, username, sizeof(g_proxy_username)-1);
    else g_proxy_username[0] = '\0';
    g_proxy_username[sizeof(g_proxy_username)-1] = '\0';
    
    if (password) strncpy(g_proxy_password, password, sizeof(g_proxy_password)-1);
    else g_proxy_password[0] = '\0';
    g_proxy_password[sizeof(g_proxy_password)-1] = '\0';
    LeaveCriticalSection(&lock_proxies);

    return TRUE;
}

NETREDIRECTOR_API UINT32 NetRedirector_AddProxyConfig(ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (!proxy_ip || !proxy_ip[0] || proxy_port == 0) return 0;
    if (resolve_hostname(proxy_ip) == 0) return 0;

    PROXY_CONFIG *config = (PROXY_CONFIG *)malloc(sizeof(PROXY_CONFIG));
    if (!config) return 0;

    memset(config, 0, sizeof(PROXY_CONFIG));
    config->proxy_id = (UINT32)InterlockedIncrement((volatile LONG*)&g_next_proxy_id);  // [Fixed] 原子遞增
    config->proxy_type = type;
    config->proxy_port = proxy_port;
    config->enabled = enabled;
    strncpy(config->proxy_ip, proxy_ip, sizeof(config->proxy_ip)-1);
    config->proxy_ip[sizeof(config->proxy_ip)-1] = '\0';
    
    if (name && name[0]) {
        strncpy(config->name, name, sizeof(config->name)-1);
        config->name[sizeof(config->name)-1] = '\0';
    }
    else snprintf(config->name, sizeof(config->name), "Proxy %u", config->proxy_id);

    if (username) {
        strncpy(config->username, username, sizeof(config->username)-1);
        config->username[sizeof(config->username)-1] = '\0';
    }
    else config->username[0] = 0;

    if (password) {
        strncpy(config->password, password, sizeof(config->password)-1);
        config->password[sizeof(config->password)-1] = '\0';
    }
    else config->password[0] = 0;

    EnterCriticalSection(&lock_proxies);
    config->next = proxy_configs;
    proxy_configs = config;
    LeaveCriticalSection(&lock_proxies);

    log_message("Added proxy config ID: %u", config->proxy_id);
    return config->proxy_id;
}

NETREDIRECTOR_API BOOL NetRedirector_EditProxyConfig(UINT32 proxy_id, ProxyType type, const char* name, const char* proxy_ip, UINT16 proxy_port, const char* username, const char* password, BOOL enabled)
{
    if (proxy_id == 0) return FALSE;
    
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->proxy_type = type;
        config->proxy_port = proxy_port;
        config->enabled = enabled;
        if (proxy_ip) { strncpy(config->proxy_ip, proxy_ip, sizeof(config->proxy_ip)-1); config->proxy_ip[sizeof(config->proxy_ip)-1] = '\0'; }
        if (name) { strncpy(config->name, name, sizeof(config->name)-1); config->name[sizeof(config->name)-1] = '\0'; }
        if (username) { strncpy(config->username, username, sizeof(config->username)-1); config->username[sizeof(config->username)-1] = '\0'; }
        if (password) { strncpy(config->password, password, sizeof(config->password)-1); config->password[sizeof(config->password)-1] = '\0'; }
        log_message("Updated proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DeleteProxyConfig(UINT32 proxy_id)
{
    if (proxy_id == 0) return FALSE;
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = proxy_configs;
    PROXY_CONFIG *prev = NULL;
    while (config) {
        if (config->proxy_id == proxy_id) {
            if (prev) prev->next = config->next;
            else proxy_configs = config->next;
            free(config);
            log_message("Deleted proxy config ID: %u", proxy_id);
            LeaveCriticalSection(&lock_proxies);
            return TRUE;
        }
        prev = config;
        config = config->next;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_EnableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = TRUE;
        log_message("Enabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_DisableProxyConfig(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *config = get_proxy_by_id(proxy_id);
    if (config) {
        config->enabled = FALSE;
        log_message("Disabled proxy config ID: %u", proxy_id);
        LeaveCriticalSection(&lock_proxies);
        return TRUE;
    }
    LeaveCriticalSection(&lock_proxies);
    return FALSE;
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetProxyConfig(UINT32 proxy_id)
{
    // NOTE: returns an internal pointer without a lock — the caller must not
    // hold the result across concurrent Edit/DeleteProxyConfig calls.
    return (PROXY_CONFIG_API*)get_proxy_by_id(proxy_id);
}

NETREDIRECTOR_API PROXY_CONFIG_API* NetRedirector_GetAllProxyConfigs(UINT32* count)
{
    if (count) {
        EnterCriticalSection(&lock_proxies);
        PROXY_CONFIG *c = proxy_configs;
        *count = 0;
        while(c) { (*count)++; c = c->next; }
        LeaveCriticalSection(&lock_proxies);
    }
    return (PROXY_CONFIG_API*)proxy_configs;
}

// === Settings APIs ===

NETREDIRECTOR_API void NetRedirector_SetDnsViaProxy(BOOL enable) { g_dns_via_proxy = enable; }
NETREDIRECTOR_API void NetRedirector_SetUnknownProcessAction(RuleAction action) { g_unknown_process_action = action; }
NETREDIRECTOR_API void NetRedirector_SetLogCallback(LogCallback callback) { g_log_callback = callback; }
NETREDIRECTOR_API void NetRedirector_SetConnectionCallback(ConnectionCallback callback) { g_connection_callback = callback; }

// === Lifecycle APIs ===

// [Added] Background DNS refresher for domain-name rules.
//
// match_ip_pattern() on the packet threads uses resolve_rule_host_cached()
// (cache-only, never blocks). This thread keeps that cache warm: it walks the
// enabled rules, snapshots their hosts fields under lock_rules, then
// re-resolves every domain pattern OUTSIDE any lock (getaddrinfo has no
// timeout and can block for seconds). It wakes immediately when a rule is
// added/edited/enabled (SetEvent) and otherwise refreshes every 30 s, so DNS
// changes propagate well inside the old 60 s TTL window.
static HANDLE dns_refresh_thread_handle = NULL;
static HANDLE dns_refresh_event = NULL;
static volatile BOOL dns_refresh_running = FALSE;

#define DNS_REFRESH_INTERVAL_MS 30000

static void signal_dns_refresh(void)
{
    if (dns_refresh_event != NULL) SetEvent(dns_refresh_event);
}

#define DNS_REFRESH_MAX_RULES 256

static DWORD WINAPI dns_refresh_worker(LPVOID arg)
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return 1;

    while (dns_refresh_running) {
        WaitForSingleObject(dns_refresh_event, DNS_REFRESH_INTERVAL_MS);
        if (!dns_refresh_running) break;

        // Snapshot the hosts fields under lock_rules; actual resolution happens
        // outside the lock so rule APIs and packet threads are never blocked.
        char *snapshots[DNS_REFRESH_MAX_RULES];
        int count = 0;
        EnterCriticalSection(&lock_rules);
        PROCESS_RULE *rule = rules_list;
        while (rule != NULL && count < DNS_REFRESH_MAX_RULES) {
            if (rule->enabled && rule->target_hosts) {
                snapshots[count] = _strdup(rule->target_hosts);
                if (snapshots[count] != NULL) count++;
            }
            rule = rule->next;
        }
        LeaveCriticalSection(&lock_rules);

        int i;
        for (i = 0; i < count; i++) {
            if (!dns_refresh_running) break;   // stop early during shutdown
            refresh_rule_dns(snapshots[i]);
        }
        for (i = 0; i < count; i++) free(snapshots[i]);
    }

    WSACleanup();
    return 0;
}

NETREDIRECTOR_API BOOL NetRedirector_Start(void)
{
    char filter[1024];
    if (running) return FALSE;

    // [Fixed] Pre-flight: verify the local relay port is bindable BEFORE
    // spawning threads. local_proxy_server binds inside its own thread and
    // would otherwise fail silently, leaving Start() reporting success while
    // every proxied connection blackholes. IPv4 bind covers the common case
    // (a dual-stack or IPv4 listener occupying the port).
    //
    // The probe deliberately does NOT set SO_REUSEADDR: a plain bind is the
    // strictest availability test — it fails whenever any socket already
    // holds the port (with or without SO_REUSEADDR). The probe socket is
    // closed immediately afterwards, so the real local_proxy_server bind is
    // unaffected.
    {
        WSADATA wsa_data;
        SOCKET probe = INVALID_SOCKET;
        struct sockaddr_in probe_addr;
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return FALSE;
        probe = socket(AF_INET, SOCK_STREAM, 0);
        if (probe == INVALID_SOCKET) {
            log_message("Local relay port probe: socket() failed (%lu); Start aborted",
                WSAGetLastError());
            WSACleanup();
            return FALSE;
        }
        memset(&probe_addr, 0, sizeof(probe_addr));
        probe_addr.sin_family = AF_INET;
        probe_addr.sin_addr.s_addr = INADDR_ANY;
        probe_addr.sin_port = htons((u_short)g_local_relay_port);
        if (bind(probe, (struct sockaddr *)&probe_addr, sizeof(probe_addr)) == SOCKET_ERROR ||
            listen(probe, SOMAXCONN) == SOCKET_ERROR) {
            log_message("Local relay port %d is in use (%lu); Start aborted",
                g_local_relay_port, WSAGetLastError());
            closesocket(probe);
            WSACleanup();
            return FALSE;
        }
        closesocket(probe);

        // [Added] UDP relay pre-flight: udp_relay_server binds inside its own
        // thread and on failure would silently return while Start() reports
        // success - every proxied UDP flow would then blackhole into port
        // %d with no listener. Probe the UDP relay port the same way.
        probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (probe == INVALID_SOCKET) {
            log_message("UDP relay port probe: socket() failed (%lu); Start aborted",
                WSAGetLastError());
            WSACleanup();
            return FALSE;
        }
        probe_addr.sin_port = htons((u_short)LOCAL_UDP_RELAY_PORT);
        if (bind(probe, (struct sockaddr *)&probe_addr, sizeof(probe_addr)) == SOCKET_ERROR) {
            log_message("UDP relay port %d is in use (%lu); Start aborted",
                LOCAL_UDP_RELAY_PORT, WSAGetLastError());
            closesocket(probe);
            WSACleanup();
            return FALSE;
        }
        closesocket(probe);
        WSACleanup();
    }

    running = TRUE;

    // [Added] Stop signal for sleeping worker threads. Created BEFORE any
    // thread that waits on it, closed only after every such thread was joined
    // in Stop(). Manual-reset so a single SetEvent wakes all current waiters.
    g_stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_stop_event == NULL) {
        log_message("Warning: failed to create stop event (%lu); worker threads "
            "fall back to timed Sleep wakeups", GetLastError());
    }

    // Cache local interface addresses for LAN on-link detection
    refresh_local_addresses();

    // Start Cleanup Thread (auxiliary: a failure here is logged, not fatal)
    extern HANDLE cleanup_thread_handle;
    cleanup_thread_handle = CreateThread(NULL, 0, cleanup_thread, NULL, 0, NULL);
    if (!cleanup_thread_handle)
        log_message("Warning: failed to create cleanup thread (%lu)", GetLastError());

    // Start Local Proxy
    proxy_thread = CreateThread(NULL, 0, local_proxy_server, NULL, 0, NULL);
    if (!proxy_thread) {
        log_message("Failed to create local proxy thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    // Start UDP Relay
    // [Fixed] 修正 CreateThread 堆疊大小: 1 → 0 (0 = 使用系統預設堆疊大小)
    udp_relay_thread = CreateThread(NULL, 0, udp_relay_server, NULL, 0, NULL);
    if (!udp_relay_thread) {
        log_message("Failed to create UDP relay thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    Sleep(500); // Give servers time to bind

    // Open WinDivert
    //
    // [Fixed] Loopback bypass at the filter layer: 127.0.0.0/8 and ::1 traffic
    // used to be captured and then re-injected unchanged ("captured
    // passthrough") after the upper-layer DIRECT checks. Every localhost
    // packet thus paid a user-mode round trip (queue -> worker -> checksum ->
    // WinDivertSend) and could be delayed or dropped under load - visible as
    // instability for local services (e.g. MySQL on 127.0.0.1) in busy
    // multi-service/Docker environments. Loopback destinations are always
    // DIRECT by policy and never proxied, so excluding them in the filter is
    // semantically identical and removes the entire overhead.
    //
    // The exclusion is written in positive/De Morgan form because the
    // WinDivert filter language has no unary NOT: "keep" = inbound, OR
    // destination-not-loopback, evaluated per family. Verified against the
    // real driver: parses OK and captures zero loopback packets.
    snprintf(filter, sizeof(filter),
        "(ip and ("
        "(tcp and (outbound or tcp.DstPort == %d or tcp.SrcPort == %d)) or "
        "(udp and (outbound or udp.DstPort == %d or udp.SrcPort == %d)"
        " and udp.DstPort != 67 and udp.SrcPort != 67"
        " and udp.DstPort != 68 and udp.SrcPort != 68))"
        " and (inbound or ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255))"
        " or "
        "(ipv6 and ("
        "(tcp and (outbound or tcp.DstPort == %d or tcp.SrcPort == %d)) or "
        "(udp and (outbound or udp.DstPort == %d or udp.SrcPort == %d)"
        " and udp.DstPort != 67 and udp.SrcPort != 67"
        " and udp.DstPort != 68 and udp.SrcPort != 68))"
        " and (inbound or ipv6.DstAddr != ::1))",
        g_local_relay_port, g_local_relay_port,
        LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT,
        g_local_relay_port, g_local_relay_port,
        LOCAL_UDP_RELAY_PORT, LOCAL_UDP_RELAY_PORT);

    windivert_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 123, 0);
    if (windivert_handle == INVALID_HANDLE_VALUE) {
        log_message("Failed to open WinDivert (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    // [Added] These are best-effort tuning knobs (16384 is the allowed max),
    // but a silent failure would leave the queue at the small default and
    // cost throughput under load - leave a trace instead.
    if (!WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_LENGTH, 16384) ||
        !WinDivertSetParam(windivert_handle, WINDIVERT_PARAM_QUEUE_TIME, 2000)) {
        log_message("Warning: WinDivertSetParam failed (%lu); using default queue limits",
            GetLastError());
    }

    // [Modified] Single receiver + flow workers (see NR_Core.c "Flow
    // Dispatch"): the receiver is the only WinDivertRecv caller, so same-flow
    // packets can no longer be re-injected out of order.
    if (!flow_queues_init()) {
        log_message("Failed to initialize flow queues (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }

    packet_threads[0] = CreateThread(NULL, 0, packet_receiver, NULL, 0, NULL);
    if (!packet_threads[0]) {
        log_message("Failed to create packet receiver thread (%lu)", GetLastError());
        running = FALSE;
        goto fail;
    }
    for (int i = 1; i < NUM_PACKET_THREADS; i++) {
        packet_threads[i] = CreateThread(NULL, 0, flow_worker, (LPVOID)(LONG_PTR)(i - 1), 0, NULL);
        if (!packet_threads[i]) {
            log_message("Failed to create flow worker thread %d (%lu)", i - 1, GetLastError());
            running = FALSE;
            goto fail;
        }
    }

    // [Added] DNS refresher for domain-name rules (keeps resolve_rule_host_
    // cached() warm so packet threads never block in getaddrinfo). Created
    // last: any earlier failure path never has to clean it up.
    dns_refresh_event = CreateEvent(NULL, FALSE, FALSE, NULL);   // auto-reset
    if (dns_refresh_event != NULL) {
        dns_refresh_running = TRUE;
        dns_refresh_thread_handle = CreateThread(NULL, 0, dns_refresh_worker, NULL, 0, NULL);
        if (dns_refresh_thread_handle == NULL) {
            log_message("Warning: failed to create DNS refresh thread (%lu); "
                "domain rules rely on cache primed at resolve time", GetLastError());
            dns_refresh_running = FALSE;
            CloseHandle(dns_refresh_event);
            dns_refresh_event = NULL;
        } else {
            SetEvent(dns_refresh_event);   // resolve existing domain rules immediately
        }
    }

    log_message("NetRedirector started. Relay: %d", g_local_relay_port);
    return TRUE;

fail:
    // running is already FALSE, so every server thread exits its loop on its
    // own. Wake the sleepers first (same as Stop), close WinDivert to unblock
    // any packet_processor threads, then wait for and close every handle that
    // was created, and reset all state. (NetRedirector_Stop() cannot be
    // reused here: it guards on `running`.)
    if (g_stop_event != NULL) SetEvent(g_stop_event);
    if (windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }
    for (int i = 0; i < NUM_PACKET_THREADS; i++) {
        if (packet_threads[i]) {
            WaitForSingleObject(packet_threads[i], 5000);
            CloseHandle(packet_threads[i]);
            packet_threads[i] = NULL;
        }
    }
    flow_queues_shutdown();
    if (proxy_thread) {
        WaitForSingleObject(proxy_thread, 5000);
        CloseHandle(proxy_thread);
        proxy_thread = NULL;
    }
    if (udp_relay_thread) {
        WaitForSingleObject(udp_relay_thread, 5000);
        CloseHandle(udp_relay_thread);
        udp_relay_thread = NULL;
    }
    if (cleanup_thread_handle) {
        WaitForSingleObject(cleanup_thread_handle, 5000);
        CloseHandle(cleanup_thread_handle);
        cleanup_thread_handle = NULL;
    }
    if (g_stop_event) { CloseHandle(g_stop_event); g_stop_event = NULL; }
    clear_connections();
    clear_logged_connections();
    clear_udp_associations();
    clear_pid_cache();
    clear_dns_cache();
    return FALSE;
}

NETREDIRECTOR_API BOOL NetRedirector_Stop(void)
{
    if (!running) return FALSE;
    running = FALSE;

    // [Added] Wake the sleeping workers (cleanup thread, DNS refresher)
    // immediately: their wait was previously a 10 s Sleep that could still be
    // running when this function returned and DllMain deleted the locks.
    if (g_stop_event != NULL) SetEvent(g_stop_event);

    if (windivert_handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivert_handle);
        windivert_handle = INVALID_HANDLE_VALUE;
    }

    // [Added] Unblock every connection/transfer thread parked in recv(): they
    // observe the shutdown as a closed socket, exit their loops and close
    // their own sockets. Without this they lingered until process exit.
    shutdown_all_connections();

    WaitForMultipleObjects(NUM_PACKET_THREADS, packet_threads, TRUE, 5000);
    for (int i=0; i<NUM_PACKET_THREADS; i++) {
        if(packet_threads[i]) { CloseHandle(packet_threads[i]); packet_threads[i]=NULL; }
    }
    // [Added] Receiver and workers are joined - safe to drain/release queues
    flow_queues_shutdown();

    if (proxy_thread) { WaitForSingleObject(proxy_thread, 5000); CloseHandle(proxy_thread); proxy_thread=NULL; }
    if (udp_relay_thread) { WaitForSingleObject(udp_relay_thread, 5000); CloseHandle(udp_relay_thread); udp_relay_thread=NULL; }
    
    // Extern handle from NR_Core.c
    extern HANDLE cleanup_thread_handle;
    if (cleanup_thread_handle) { WaitForSingleObject(cleanup_thread_handle, 5000); CloseHandle(cleanup_thread_handle); cleanup_thread_handle=NULL; }

    // [Added] Stop the DNS refresher: wake it from the wait, let it observe
    // dns_refresh_running == FALSE and exit. If it is stuck inside a slow
    // getaddrinfo the 5 s wait simply gives up (same policy as the other
    // threads above).
    if (dns_refresh_thread_handle) {
        dns_refresh_running = FALSE;
        signal_dns_refresh();
        WaitForSingleObject(dns_refresh_thread_handle, 5000);
        CloseHandle(dns_refresh_thread_handle);
        dns_refresh_thread_handle = NULL;
    }
    if (dns_refresh_event) { CloseHandle(dns_refresh_event); dns_refresh_event = NULL; }

    // [Added] Every thread that waits on the stop event has been joined by
    // now - safe to release it.
    if (g_stop_event) { CloseHandle(g_stop_event); g_stop_event = NULL; }

    clear_connections();
    clear_logged_connections();
    clear_udp_associations(); // Clean sockets
    clear_pid_cache();        // Drop stale PID/process-name cache entries
    clear_dns_cache();        // [Added] Drop stale domain-rule DNS resolution cache

    log_message("NetRedirector stopped");
    return TRUE;
}

// === DllMain ===

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            g_current_process_id = GetCurrentProcessId();
            InitializeCriticalSection(&lock_rules);
            InitializeCriticalSection(&lock_connections);
            InitializeCriticalSection(&lock_logged);
            InitializeCriticalSection(&lock_proxies);
            InitializeCriticalSection(&lock_udp);
            InitializeCriticalSection(&lock_pid_cache);
            break;

        case DLL_PROCESS_DETACH:
            // [Fixed] Loader-lock deadlock: during process termination
            // (lpReserved != NULL) the loader holds the loader lock, and
            // NetRedirector_Stop() waits on threads that may be calling
            // CreateThread (connection_handler -> transfer_handler), which
            // itself needs the loader lock -> deadlock. Only run the full
            // stop for an explicit FreeLibrary unload; at process exit the OS
            // is tearing all threads down anyway, so just flag stopped and
            // release memory.
            if (lpReserved == NULL && running) NetRedirector_Stop();
            else running = FALSE;
            
            // Clean global lists
            while (rules_list) {
                PROCESS_RULE *n = rules_list->next;
                free(rules_list->target_hosts); free(rules_list->target_ports); free(rules_list);
                rules_list = n;
            }
            clear_proxy_configs();
            
            DeleteCriticalSection(&lock_rules);
            DeleteCriticalSection(&lock_connections);
            DeleteCriticalSection(&lock_logged);
            DeleteCriticalSection(&lock_proxies);
            DeleteCriticalSection(&lock_udp);
            DeleteCriticalSection(&lock_pid_cache);
            break;
    }
    return TRUE;
}