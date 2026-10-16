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

RuleAction check_process_rule(int family, const UINT8 *src_addr, UINT16 src_port, const UINT8 *dest_addr, UINT16 dest_port, BOOL is_udp, UINT32* out_proxy_id, DWORD pid_in, BOOL have_pid)
{
    DWORD pid;
    char process_name[MAX_PROCESS_NAME];
    UINT32 selected_proxy_id = 0;

    if (have_pid) {
        // [Perf] The caller already ran the whole resolution chain (result
        // cache -> event map -> GetExtendedTcpTable) for this exact
        // (family, src_addr, src_port, is_udp), microseconds ago. Re-running it
        // here was pure duplication, and it was NOT free: a failed resolution
        // is deliberately not cached (see the pid == 0 early-return in
        // pid_result_cache_store), so the duplicate cost another full
        // GetExtendedTcpTable - ~650 us per unresolvable new connection, i.e.
        // 2x per occurrence. Same inputs microseconds apart give the same
        // answer, so the second query can only ever have repeated the first.
        pid = pid_in;
    } else if (family == AF_INET6) {
        pid = is_udp ? get_process_id_from_udp_connection6(src_addr, src_port)
                     : get_process_id_from_connection6(src_addr, src_port, dest_addr, dest_port);
        if (pid == 0 && is_udp) pid = get_process_id_from_connection6(src_addr, src_port, dest_addr, dest_port);
    } else {
        UINT32 src_ip = 0, dest_ip = 0;
        memcpy(&src_ip, src_addr, 4);
        memcpy(&dest_ip, dest_addr, 4);
        pid = is_udp ? get_process_id_from_udp_connection(src_ip, src_port)
                     : get_process_id_from_connection(src_ip, src_port, dest_ip, dest_port);
        if (pid == 0 && is_udp) pid = get_process_id_from_connection(src_ip, src_port, dest_ip, dest_port);
    }

    if (pid == 0) {
        // [Added] The flow could not be attributed to any process, so the
        // configured "unknown process" action is applied - by default DIRECT.
        // With a catch-all PROXY rule in the list this silently means "this
        // connection bypasses the proxy", and nothing anywhere said so. It is
        // one of the two ways a working proxy setup can appear to die on
        // restart while the rules themselves look perfectly configured.
        //
        // Both endpoints are logged. The local one is what the table lookup
        // keys on, so without it there is no way to tell an ordinary client
        // flow apart from a packet the engine is re-classifying on its own
        // relay port - and the relay case used to be the bulk of these lines.
        char src_str[MAX_IP_STR];
        char dest_str[MAX_IP_STR];
        addr_to_string(family, src_addr, src_str, sizeof(src_str));
        addr_to_string(family, dest_addr, dest_str, sizeof(dest_str));

        // [Added] DNS is the one case where the fallback below does not just
        // err on the safe side - it contradicts a setting.
        //
        // g_dns_via_proxy defaults to TRUE, i.e. "DNS goes through the proxy"
        // (it is the whole point of the socks5h path: the proxy resolves, so no
        // cleartext query leaves the machine). An attributed DNS flow reaches
        // the rules and therefore the proxy whenever a catch-all PROXY rule is
        // configured. An unattributed one - routine for UDP, the client socket
        // is usually gone before the table lookup - used to stop here and go
        // DIRECT. Same setting, two different outcomes, and the leaky half is
        // invisible: the datagram is forwarded unchanged and looks normal.
        //
        // So for port 53 fall through to match_rule() with an empty process
        // name instead, exactly like the "pid we cannot name" case below: the
        // rules that can still be evaluated (wildcard, PID, domain) decide, and
        // name-specific rules simply miss. With g_dns_via_proxy off the
        // preference wins outright - no rule may put DNS on the proxy.
        char disposition[160];
        if (dest_port == 53) {
            snprintf(disposition, sizeof(disposition), g_dns_via_proxy
                ? "DNS with dns_via_proxy on, so the rules are evaluated with "
                  "an empty process name (process-name rules cannot match)"
                : "applying DIRECT (DNS with dns_via_proxy off)");
        } else {
            snprintf(disposition, sizeof(disposition),
                "applying unknown-process action %d - process-name rules "
                "cannot match it", (int)g_unknown_process_action);
        }

        // UDP gets its own, much longer window: an unattributable UDP datagram
        // is routine (the socket is usually gone before the lookup - see
        // NR_THROTTLE_UNKNOWN_PID_UDP in NR_Common.h) and it is forwarded
        // unchanged, whereas the identical TCP line is a real signal. Sharing
        // one slot let a single DNS client drown out the TCP case.
        log_message_throttled(is_udp ? NR_THROTTLE_UNKNOWN_PID_UDP
                                     : NR_THROTTLE_UNKNOWN_PID,
            is_udp ? NR_THROTTLE_UNKNOWN_PID_UDP_MS : 5000,
            "Flow %s:%u -> %s:%u (family %d, %s) could not be attributed to a "
            "process; %s",
            src_str, (unsigned)src_port, dest_str, (unsigned)dest_port,
            family, is_udp ? "UDP" : "TCP", disposition);

        if (dest_port != 53) {
            *out_proxy_id = 0;
            return g_unknown_process_action;
        }
        if (!g_dns_via_proxy) {
            *out_proxy_id = 0;
            return RULE_ACTION_DIRECT;
        }
        // DNS with dns_via_proxy on: fall through with an empty process name.
    } else {
        // Loop prevention: bypass own process
        if (pid == g_current_process_id) return RULE_ACTION_DIRECT;
    }

    // [Changed] A pid we cannot name is no longer an automatic DIRECT.
    //
    // get_process_name_from_pid() fails when OpenProcess is denied - a process
    // created by a different, non-elevated account (see enable_debug_privilege()
    // in NetRedirector.c) or a protected one. Returning g_unknown_process_action
    // here short-circuited match_rule() entirely, so even a catch-all
    // "*" -> PROXY rule was bypassed and the flow went direct with no
    // explanation: an RDP session's traffic silently ignored a working proxy.
    //
    // Falling through with an empty name lets the rules that CAN still be
    // evaluated decide: PID rules match on the pid, wildcard rules match
    // regardless of the name, and only rules that ask for a specific name miss.
    // If nothing matches, match_rule() returns DIRECT on its own - so the worst
    // case is exactly what it was, while the common case (a catch-all rule) now
    // behaves the way the user configured it.
    //
    // pid == 0 also lands here (the DNS case above): the call is a no-op that
    // returns FALSE for it, leaving the empty name the fall-through wanted.
    if (!get_process_name_from_pid(pid, process_name, sizeof(process_name))) {
        process_name[0] = '\0';
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
            if (!usable) {
                // [Added] A PROXY rule whose proxy is missing or disabled is
                // downgraded to DIRECT with no trace at all. That is the most
                // likely way "everything is proxied" becomes "nothing is
                // proxied" after a restart (the rule is re-added before or
                // without its proxy), and it is invisible from the UI.
                log_message_throttled(NR_THROTTLE_PROXY_DOWNGRADE, 5000,
                    "Rule requested PROXY with proxy_id=%u, which is %s; "
                    "downgrading this flow to DIRECT",
                    selected_proxy_id, (cfg == NULL) ? "not registered" : "disabled");
                return RULE_ACTION_DIRECT;
            }
        } else {
            EnterCriticalSection(&lock_proxies);
            BOOL has_default = (g_proxy_ip[0] != '\0' && g_proxy_port != 0);
            LeaveCriticalSection(&lock_proxies);
            if (!has_default) {
                // [Added] No per-rule proxy and no default proxy either. Note
                // that NetRedirector_AddProxyConfig() does NOT populate the
                // g_proxy_* globals - only NetRedirector_SetProxyConfig() does -
                // so a rule added with proxy_id=0 can never resolve a proxy
                // here, whatever proxies exist in the list.
                log_message_throttled(NR_THROTTLE_PROXY_DOWNGRADE, 5000,
                    "Rule requested PROXY with no proxy_id and no default proxy "
                    "configured (g_proxy_ip is empty); downgrading this flow to DIRECT");
                return RULE_ACTION_DIRECT;
            }
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
    //
    // The remote endpoint goes in as well: the TCP table is keyed per
    // connection, so (local addr, local port) alone is not unique and a closed
    // connection's TIME_WAIT row (owning pid 0) can sit under the same key as
    // a live one. See scan_tcp_table_v4() in NR_Utils.c.
    char process_path[MAX_PROCESS_NAME];
    DWORD pid;
    if (family == AF_INET6) {
        if (is_udp) {
            pid = get_process_id_from_udp_connection6(src_addr, src_port);
            if (pid == 0) pid = get_process_id_from_connection6(src_addr, src_port, dest_addr, dest_port);
        } else {
            pid = get_process_id_from_connection6(src_addr, src_port, dest_addr, dest_port);
        }
    } else {
        UINT32 src_ip = 0, dest_ip = 0;
        memcpy(&src_ip, src_addr, 4);
        memcpy(&dest_ip, dest_addr, 4);
        if (is_udp) {
            pid = get_process_id_from_udp_connection(src_ip, src_port);
            if (pid == 0) pid = get_process_id_from_connection(src_ip, src_port, dest_ip, dest_port);
        } else {
            pid = get_process_id_from_connection(src_ip, src_port, dest_ip, dest_port);
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
            action = check_process_rule(family, src_addr, src_port, dest_addr, dest_port, is_udp, selected_proxy_id, pid, TRUE);
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
        // [Perf] `pid` is 0 here (or the name lookup failed) - but the full
        // resolution chain was ALREADY run above. Hand it over instead of
        // letting check_process_rule re-run it, which cost a second
        // GetExtendedTcpTable (~650 us) whenever the pid could not be resolved.
        action = check_process_rule(family, src_addr, src_port, dest_addr, dest_port, is_udp, selected_proxy_id, pid, TRUE);
    }

    return action;
}