// --- START OF FILE NR_State.h ---
#ifndef NR_STATE_H
#define NR_STATE_H

#include "NR_Common.h"

// === Global Lists (Defined in NR_State.c) ===
extern CONNECTION_INFO *connection_list;
extern LOGGED_CONNECTION *logged_connections;
extern PROCESS_RULE *rules_list;
extern UDP_ASSOCIATION *udp_associations;
// proxy_configs is already extern in NR_Common.h

// === Connection Tracking ===
// TCP entries: keyed by (src_port + family + original destination address).
// A recycled ephemeral port opening a NEW connection to a different
// destination must never satisfy an old entry's lookup (it would be silently
// rerouted through the old flow's proxy path before rule evaluation).
// UDP entries: keyed by (src_port + family + orig destination) so one app
// socket can talk to multiple destinations.
void add_connection(UINT16 src_port, int family, const UINT8 *src_addr, const UINT8 *dest_addr, UINT16 dest_port, UINT32 proxy_id, RuleAction action, BOOL is_udp);
BOOL get_connection(UINT16 src_port, int family, const UINT8 *dest_key, int *out_family, UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id, RuleAction *action);   // TCP full-key lookup
BOOL is_connection_tracked(UINT16 src_port, int family, const UINT8 *dest_key);                                      // TCP full-key lookup
BOOL get_connection_udp(UINT16 src_port, int family, const UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id);   // UDP full-key lookup
BOOL is_connection_tracked_udp(UINT16 src_port, int family, const UINT8 *dest_addr);                                 // UDP full-key lookup
BOOL get_udp_dest_port_for_app(UINT16 src_port, UINT16 *dest_port);             // UDP relay->app response rewrite
void remove_connection(UINT16 src_port, int family, const UINT8 *dest_key);
void clear_connections(); // New helper

// === Logged Connections (Deduplication) ===
BOOL is_connection_already_logged(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action);
void add_logged_connection(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action);
void clear_logged_connections();
void prune_logged_connections(DWORD now_ms, DWORD ttl_ms);

// === Proxy Config Management ===
PROXY_CONFIG* get_proxy_by_id(UINT32 proxy_id);
void clear_proxy_configs(); // New helper

// === UDP Association Management ===
void add_udp_association(UDP_ASSOCIATION* assoc);
void remove_udp_association(UDP_ASSOCIATION* assoc);
void clear_udp_associations(); // New helper

#endif // NR_STATE_H