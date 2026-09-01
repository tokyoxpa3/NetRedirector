// --- FILE: NR_Utils.h ---
#ifndef NR_UTILS_H
#define NR_UTILS_H

#include "NR_Common.h"

// Networking & Strings
UINT32 parse_ipv4(const char *ip);
UINT32 resolve_hostname(const char *hostname);
BOOL resolve_hostname6(const char *hostname, UINT8 *out_addr6);   // [Added] IPv6 hostname resolution
UINT32 resolve_rule_host(const char *host);   // [Added] DNS-cached hostname resolution for domain rules
UINT32 resolve_rule_host_cached(const char *host); // [Added] cache-only lookup for the packet-thread match path
void force_resolve_rule_host(const char *host);    // [Added] unconditional resolve+store for the background refresher
BOOL resolve_rule_host_cached6(const char *host, UINT8 *out_addr6); // [Added] IPv6 cache-only lookup (packet-thread safe)
void force_resolve_rule_host6(const char *host);    // [Added] unconditional IPv6 resolve+store
void refresh_rule_dns(const char *hosts_field);    // [Added] pre-resolve all domain patterns in one rule's hosts field
void clear_dns_cache(void);                   // [Added] Clear the DNS resolution cache

// === DNS Snooping (wildcard-subdomain matching) ===
void dns_snoop_record(UINT32 ip, const char *domain);              // [Added] record one IPv4->domain mapping
void dns_snoop_record6(const UINT8 *addr6, const char *domain);    // [Added] record one IPv6->domain mapping
BOOL dns_snoop_matches_suffix(UINT32 ip, const char *suffix);      // [Added] IPv4 cache-only suffix lookup (packet-thread safe)
BOOL dns_snoop_matches_suffix6(const UINT8 *addr6, const char *suffix); // [Added] IPv6 cache-only suffix lookup
int dns_snoop_parse_response(const UINT8 *msg, UINT msg_len);      // [Added] parse a DNS response, record A/AAAA records
void clear_dns_snoop_cache(void);                                  // [Added] clear the addr->domain snoop cache
const char* extract_filename(const char* path);
void EnableKeepAlive(SOCKET s);
BOOL connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, DWORD timeout_ms);   // [Added] bounded connect for proxy dial-outs
void base64_encode(const char* input, char* output, size_t output_size);

// Process ID & Name Resolution
DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port);
DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port);
DWORD get_process_id_from_connection6(const UINT8 *src_ip6, UINT16 src_port);
DWORD get_process_id_from_udp_connection6(const UINT8 *src_ip6, UINT16 src_port);
BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size);
void clear_pid_cache(void);

// IPv6 Helpers
void addr_to_string(int family, const UINT8 *addr, char *buf, size_t size);
BOOL is_multicast_or_special6(const UINT8 *a);

// LAN / On-link Detection
void refresh_local_addresses(void);
BOOL is_lan_or_on_link_address(int family, const UINT8 *addr);

// Matching Logic
// [Fixed] 萬用字元辨識: 半形 "*"、字面 "ANY"，以及全形 "＊" (U+FF0A, UTF-8 EF BC 8A)
// 全形星號常見於中文輸入法；若不處理，規則永不匹配、流量會走直連
#define is_wildcard_str(s) ((s) != NULL && (strcmp((s), "*") == 0 || strcmp((s), "ANY") == 0 || strcmp((s), "\xEF\xBC\x8A") == 0))

BOOL match_ip_pattern(const char *pattern, UINT32 ip);
BOOL match_port_pattern(const char *pattern, UINT16 port);
BOOL match_ip_list(const char *ip_list, UINT32 ip);
BOOL match_port_list(const char *port_list, UINT16 port);
BOOL match_ip_pattern6(const char *pattern, const UINT8 *ip);
BOOL match_ip_list6(const char *ip_list, const UINT8 *ip);
BOOL match_process_pattern(const char *pattern, const char *process_full_path);
BOOL match_process_list(const char *process_list, const char *process_name);
BOOL is_broadcast_or_multicast(UINT32 ip);

#endif // NR_UTILS_H