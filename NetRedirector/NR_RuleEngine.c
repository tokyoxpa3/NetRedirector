// --- START OF FILE NR_RuleEngine.c ---
#include "NR_RuleEngine.h"

RuleAction match_rule(DWORD current_pid, const char *process_name, int family, const UINT8 *dest_addr, UINT16 dest_port, BOOL is_udp, UINT32* out_proxy_id)
{
    EnterCriticalSection(&lock_rules);

    PROCESS_RULE *rule = rules_list;
    PROCESS_RULE *wildcard_rule = NULL;

    if (out_proxy_id != NULL) *out_proxy_id = 0;

    while (rule != NULL)
    {
        if (!rule->enabled) {
            rule = rule->next;
            continue;
        }

        if (rule->protocol != RULE_PROTOCOL_BOTH) {
            if (rule->protocol == RULE_PROTOCOL_TCP && is_udp) { rule = rule->next; continue; }
            if (rule->protocol == RULE_PROTOCOL_UDP && !is_udp) { rule = rule->next; continue; }
        }

        // Prioritize PID rules
        if (rule->target_pid != 0) {
            if (rule->target_pid == current_pid) {
                 // PID matches, now check IP/Port
                 BOOL ip_ok = (family == AF_INET6) ? match_ip_list6(rule->target_hosts, dest_addr)
                                                   : match_ip_list(rule->target_hosts, *(UINT32*)dest_addr);
                 if (ip_ok && match_port_list(rule->target_ports, dest_port)) {
                     if (out_proxy_id) *out_proxy_id = rule->proxy_id;
                     LeaveCriticalSection(&lock_rules);
                     return rule->action;
                 }
            }
            // If PID doesn't match, continue to next rule (skip name matching)
            rule = rule->next;
            continue;
        }

        // [Fixed] 支援全形 "＊" 作為萬用字元 (is_wildcard_str 亦認得 "ANY")
        BOOL is_wildcard_process = is_wildcard_str(rule->process_name);

        if (is_wildcard_process) {
            BOOL has_ip_filter = !is_wildcard_str(rule->target_hosts);
            BOOL has_port_filter = !is_wildcard_str(rule->target_ports);

            if (has_ip_filter || has_port_filter) {
                BOOL ip_ok = (family == AF_INET6) ? match_ip_list6(rule->target_hosts, dest_addr)
                                                  : match_ip_list(rule->target_hosts, *(UINT32*)dest_addr);
                if (ip_ok && match_port_list(rule->target_ports, dest_port)) {
                    if (out_proxy_id) *out_proxy_id = rule->proxy_id;
                    LeaveCriticalSection(&lock_rules);
                    return rule->action;
                }
                rule = rule->next;
                continue;
            }
            if (wildcard_rule == NULL) wildcard_rule = rule;
            rule = rule->next;
            continue;
        }

        if (match_process_list(rule->process_name, process_name)) {
            BOOL ip_ok = (family == AF_INET6) ? match_ip_list6(rule->target_hosts, dest_addr)
                                              : match_ip_list(rule->target_hosts, *(UINT32*)dest_addr);
            if (ip_ok && match_port_list(rule->target_ports, dest_port)) {
                if (out_proxy_id) *out_proxy_id = rule->proxy_id;
                LeaveCriticalSection(&lock_rules);
                return rule->action;
            }
        }
        rule = rule->next;
    }

    if (wildcard_rule != NULL) {
        if (out_proxy_id) *out_proxy_id = wildcard_rule->proxy_id;
        LeaveCriticalSection(&lock_rules);
        return wildcard_rule->action;
    }

    LeaveCriticalSection(&lock_rules);
    return RULE_ACTION_DIRECT;
}

RuleAction check_process_rule(int family, const UINT8 *src_addr, UINT16 src_port, const UINT8 *dest_addr, UINT16 dest_port, BOOL is_udp, UINT32* out_proxy_id)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];
    UINT32 selected_proxy_id = 0;

    if (family == AF_INET6) {
        pid = is_udp ? get_process_id_from_udp_connection6(src_addr, src_port) : get_process_id_from_connection6(src_addr, src_port);
        if (pid == 0 && is_udp) pid = get_process_id_from_connection6(src_addr, src_port);
    } else {
        UINT32 src_ip = 0;
        memcpy(&src_ip, src_addr, 4);
        pid = is_udp ? get_process_id_from_udp_connection(src_ip, src_port) : get_process_id_from_connection(src_ip, src_port);
        if (pid == 0 && is_udp) pid = get_process_id_from_connection(src_ip, src_port);
    }

    if (pid == 0) {
        *out_proxy_id = 0;
        return g_unknown_process_action;
    }

    // Loop prevention: bypass own process
    if (pid == g_current_process_id) return RULE_ACTION_DIRECT;

    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name))) {
        *out_proxy_id = 0;
        return g_unknown_process_action;
    }

    RuleAction action = match_rule(pid, process_name, family, dest_addr, dest_port, is_udp, &selected_proxy_id);

    // UDP & HTTP Proxy check (reads proxy configs, guarded by lock_proxies)
    if (action == RULE_ACTION_PROXY && is_udp) {
        ProxyType p_type;
        EnterCriticalSection(&lock_proxies);
        PROXY_CONFIG* proxy_config = NULL;
        if (selected_proxy_id != 0) {
            proxy_config = get_proxy_by_id(selected_proxy_id);
        }
        p_type = (proxy_config != NULL) ? proxy_config->proxy_type : g_proxy_type;
        LeaveCriticalSection(&lock_proxies);

        if (p_type == PROXY_TYPE_HTTP) {
            return RULE_ACTION_DIRECT; // HTTP proxy doesn't support UDP
        }
    }

    // Validation: proxy config must be present and enabled
    if (action == RULE_ACTION_PROXY) {
        if (selected_proxy_id != 0) {
            EnterCriticalSection(&lock_proxies);
            PROXY_CONFIG* cfg = get_proxy_by_id(selected_proxy_id);
            BOOL usable = (cfg != NULL && cfg->enabled);
            LeaveCriticalSection(&lock_proxies);
            if (!usable) return RULE_ACTION_DIRECT;
        } else {
            EnterCriticalSection(&lock_proxies);
            BOOL has_default = (g_proxy_ip[0] != '\0' && g_proxy_port != 0);
            LeaveCriticalSection(&lock_proxies);
            if (!has_default) return RULE_ACTION_DIRECT;
        }
    }

    if (out_proxy_id != NULL) *out_proxy_id = selected_proxy_id;
    return action;
}

RuleAction handle_new_connection_logic(int family, const UINT8 *src_addr, const UINT8 *dest_addr, UINT16 src_port, UINT16 dest_port, BOOL is_udp, UINT32* selected_proxy_id)
{
    RuleAction action;
    UINT32 proxy_id_cache;
    UINT8 dest_addr_cache[16];
    UINT16 dest_port_cache;

    // Check cache (TCP entries only, full key: port + family + destination).
    // A UDP flow can at worst hit a same-port TCP entry to the identical
    // destination - vanishingly rare - and otherwise falls through to fresh
    // classification below.
    if (get_connection(src_port, family, dest_addr, NULL, dest_addr_cache, &dest_port_cache, &proxy_id_cache, &action)) {
        *selected_proxy_id = proxy_id_cache;
        return action;
    }

    // DHCP / Broadcast checks
    if (is_udp && (dest_port == 67 || dest_port == 68 || src_port == 67 || src_port == 68)) {
        *selected_proxy_id = 0;
        return RULE_ACTION_DIRECT;
    }
    if (family == AF_INET6) {
        if (is_multicast_or_special6(dest_addr)) {
            *selected_proxy_id = 0;
            return RULE_ACTION_DIRECT;
        }
    } else {
        UINT32 dest_ip = 0;
        memcpy(&dest_ip, dest_addr, 4);
        if (is_broadcast_or_multicast(dest_ip)) {
            *selected_proxy_id = 0;
            return RULE_ACTION_DIRECT;
        }
    }

    // LAN / On-link bypass: local network traffic (IPv4 private ranges,
    // IPv6 ULA, or any destination in a subnet we are directly connected to)
    // must never be routed through an external proxy.
    if (is_lan_or_on_link_address(family, dest_addr)) {
        *selected_proxy_id = 0;
        return RULE_ACTION_DIRECT;
    }

    // Process Lookup
    char process_path[MAX_PROCESS_NAME];
    DWORD pid;
    if (family == AF_INET6) {
        if (is_udp) {
            pid = get_process_id_from_udp_connection6(src_addr, src_port);
            if (pid == 0) pid = get_process_id_from_connection6(src_addr, src_port);
        } else {
            pid = get_process_id_from_connection6(src_addr, src_port);
        }
    } else {
        UINT32 src_ip = 0;
        memcpy(&src_ip, src_addr, 4);
        if (is_udp) {
            pid = get_process_id_from_udp_connection(src_ip, src_port);
            if (pid == 0) pid = get_process_id_from_connection(src_ip, src_port);
        } else {
            pid = get_process_id_from_connection(src_ip, src_port);
        }
    }

    if (pid > 0 && get_process_name_from_pid(pid, process_path, sizeof(process_path))) {
        const char* filename = extract_filename(process_path);

        // SoftEther / VPN Loop prevention
        if (_stricmp(filename, "vpnclient_x64.exe") == 0 || _stricmp(filename, "vpnclient.exe") == 0 ||
            _stricmp(filename, "vpncmgr_x64.exe") == 0 || _stricmp(filename, "vpncmgr.exe") == 0) {
            action = RULE_ACTION_DIRECT;
            *selected_proxy_id = 0;
        }
        else if (dest_port == 53 && !g_dns_via_proxy) {
            action = RULE_ACTION_DIRECT;
            *selected_proxy_id = 0;
        }
        else {
            action = check_process_rule(family, src_addr, src_port, dest_addr, dest_port, is_udp, selected_proxy_id);
        }

        // Logging
        if (g_connection_callback != NULL && !is_connection_already_logged(pid, family, dest_addr, dest_port, action)) {
            char dest_ip_str[MAX_IP_STR];
            char proxy_info[128] = "Direct";
            addr_to_string(family, dest_addr, dest_ip_str, sizeof(dest_ip_str));
            
            if (action == RULE_ACTION_PROXY) snprintf(proxy_info, sizeof(proxy_info), "Proxy");
            else if (action == RULE_ACTION_BLOCK) snprintf(proxy_info, sizeof(proxy_info), "Blocked");
            
            char full_msg[256];
            snprintf(full_msg, sizeof(full_msg), "%s (%s)", proxy_info, is_udp ? "UDP" : "TCP");
            g_connection_callback(filename, pid, dest_ip_str, dest_port, full_msg);
            add_logged_connection(pid, family, dest_addr, dest_port, action);
        }
    } else {
        action = check_process_rule(family, src_addr, src_port, dest_addr, dest_port, is_udp, selected_proxy_id);
    }

    return action;
}