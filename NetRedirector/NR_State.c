// --- START OF FILE NR_State.c ---
#include "NR_State.h"

// Define Global Lists
CONNECTION_INFO *connection_list = NULL;
LOGGED_CONNECTION *logged_connections = NULL;
PROCESS_RULE *rules_list = NULL;
UDP_ASSOCIATION *udp_associations = NULL;
PROXY_CONFIG *proxy_configs = NULL;

// Define ID Counters
// [Fixed] 從 0 起算: 分配用 InterlockedIncrement (先加再回傳), 第一個 ID 仍為 1
UINT32 g_next_rule_id = 0;
UINT32 g_next_proxy_id = 0;

// === Connection Tracking ===
// (protected by lock_connections)
//
// Keying: TCP entries are keyed by (src_port + family + original destination
// address). A src_port-only key was removed: when an app dies without FIN/RST
// the entry lingers until the timeout sweep, and Windows aggressively recycles
// ephemeral ports - the next connection from the same port to a DIFFERENT
// destination (e.g. a LAN host) would then be hijacked into the old flow's
// proxy path before rule/LAN evaluation ever ran. With the destination in the
// key, such packets miss the stale entry and get classified as a new
// connection; both entries coexist harmlessly until they time out.
// UDP entries are keyed by (src_port + family + original destination): a
// single UDP socket commonly sends to several destinations (DNS resolver
// rotation, QUIC, game server lists), and each destination must keep its own
// tracked port/proxy mapping or packets for the second destination would be
// relayed to the first one's server.

void add_connection(UINT16 src_port, int family, const UINT8 *src_addr, const UINT8 *dest_addr, UINT16 dest_port, UINT32 proxy_id, RuleAction action, BOOL is_udp)
{
    EnterCriticalSection(&lock_connections);

    CONNECTION_INFO *existing = connection_list;
    while (existing != NULL) {
        BOOL same_key = FALSE;
        if (existing->src_port == src_port) {
            int n = (family == AF_INET) ? 4 : 16;
            if (is_udp) {
                same_key = existing->is_udp && existing->family == family &&
                           dest_addr != NULL &&
                           memcmp(existing->orig_dest_addr, dest_addr, n) == 0;
            } else {
                // [Fixed] TCP key now includes family + original destination:
                // same-port entries for different destinations coexist instead
                // of silently overwriting each other.
                same_key = !existing->is_udp && existing->family == family &&
                           dest_addr != NULL &&
                           memcmp(existing->orig_dest_addr, dest_addr, n) == 0;
            }
        }
        if (same_key) {
            existing->family = family;
            if (src_addr) memcpy(existing->src_addr, src_addr, 16);
            if (dest_addr) memcpy(existing->orig_dest_addr, dest_addr, 16);
            existing->orig_dest_port = dest_port;
            existing->proxy_id = proxy_id;
            existing->action = action;
            existing->is_udp = is_udp;
            existing->last_activity = GetTickCount();
            LeaveCriticalSection(&lock_connections);
            return;
        }
        existing = existing->next;
    }

    CONNECTION_INFO *conn = (CONNECTION_INFO *)malloc(sizeof(CONNECTION_INFO));
    if (conn == NULL) {
        LeaveCriticalSection(&lock_connections);
        return;
    }

    conn->src_port = src_port;
    conn->family = family;
    memset(conn->src_addr, 0, 16);
    memset(conn->orig_dest_addr, 0, 16);
    if (src_addr) memcpy(conn->src_addr, src_addr, 16);
    if (dest_addr) memcpy(conn->orig_dest_addr, dest_addr, 16);
    conn->orig_dest_port = dest_port;
    conn->proxy_id = proxy_id;
    conn->action = action;
    conn->is_udp = is_udp;
    conn->last_activity = GetTickCount();
    conn->next = connection_list;
    connection_list = conn;
    LeaveCriticalSection(&lock_connections);
}

// [Modified] TCP lookup: key = (src_port + family + original destination
// address). Callers pass the packet's destination address for outbound packets,
// or the app-endpoint address for relay-returning packets (which equals the
// stored original destination - see the NAT swap in process_packet).
// dest_key length follows family (4/16 bytes); NULL key is always a miss.
BOOL get_connection(UINT16 src_port, int family, const UINT8 *dest_key, int *out_family, UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id, RuleAction *action)
{
    BOOL found = FALSE;
    if (dest_key == NULL) return FALSE;
    int n = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;

    while (conn != NULL)
    {
        // TCP semantics: same-port UDP entries (different sockets can share a
        // port number) never satisfy a TCP lookup.
        if (conn->src_port == src_port && !conn->is_udp &&
            conn->family == family &&
            memcmp(conn->orig_dest_addr, dest_key, n) == 0)
        {
            if (out_family) *out_family = conn->family;
            if (dest_addr) memcpy(dest_addr, conn->orig_dest_addr, 16);
            if (dest_port) *dest_port = conn->orig_dest_port;
            if (proxy_id) *proxy_id = conn->proxy_id;
            if (action) *action = conn->action;

            conn->last_activity = GetTickCount();
            found = TRUE;

            // Move to front optimization
            if (prev != NULL)
            {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_connections);
    return found;
}

BOOL is_connection_tracked(UINT16 src_port, int family, const UINT8 *dest_key)
{
    BOOL tracked = FALSE;
    if (dest_key == NULL) return FALSE;
    int n = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;
    while (conn != NULL) {
        if (conn->src_port == src_port && !conn->is_udp &&
            conn->family == family &&
            memcmp(conn->orig_dest_addr, dest_key, n) == 0)
        {
            tracked = TRUE;
            if (prev != NULL) {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_connections);
    return tracked;
}

// [Added] UDP-keyed lookups: key = (src_port + family + original destination).
// Used by the packet processor's UDP branch and by the UDP relay, which knows
// the true destination IP from the swapped source address of the re-injected
// packet.
BOOL get_connection_udp(UINT16 src_port, int family, const UINT8 *dest_addr, UINT16 *dest_port, UINT32 *proxy_id)
{
    BOOL found = FALSE;
    if (dest_addr == NULL) return FALSE;
    int n = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;
    while (conn != NULL) {
        if (conn->is_udp && conn->src_port == src_port && conn->family == family &&
            memcmp(conn->orig_dest_addr, dest_addr, n) == 0)
        {
            if (dest_port) *dest_port = conn->orig_dest_port;
            if (proxy_id) *proxy_id = conn->proxy_id;
            conn->last_activity = GetTickCount();
            found = TRUE;
            if (prev != NULL) {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_connections);
    return found;
}

BOOL is_connection_tracked_udp(UINT16 src_port, int family, const UINT8 *dest_addr)
{
    BOOL tracked = FALSE;
    if (dest_addr == NULL) return FALSE;
    int n = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO *conn = connection_list;
    CONNECTION_INFO *prev = NULL;
    while (conn != NULL) {
        if (conn->is_udp && conn->src_port == src_port && conn->family == family &&
            memcmp(conn->orig_dest_addr, dest_addr, n) == 0)
        {
            tracked = TRUE;
            if (prev != NULL) {
                prev->next = conn->next;
                conn->next = connection_list;
                connection_list = conn;
            }
            break;
        }
        prev = conn;
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_connections);
    return tracked;
}

// [Added] For rewriting relay->app UDP responses: recovers an original
// destination port for the app port. With multiple destinations behind one
// socket this returns the most recently used entry's port - when two
// destinations share the same service port (DNS 53, QUIC 443) this is exact;
// mixed ports on one socket are a rare residual limitation of the
// relay-port-rewrite design.
BOOL get_udp_dest_port_for_app(UINT16 src_port, UINT16 *dest_port)
{
    BOOL found = FALSE;
    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO *conn = connection_list;
    while (conn != NULL) {
        if (conn->is_udp && conn->src_port == src_port) {
            if (dest_port) *dest_port = conn->orig_dest_port;
            found = TRUE;
            break;
        }
        conn = conn->next;
    }
    LeaveCriticalSection(&lock_connections);
    return found;
}

void remove_connection(UINT16 src_port, int family, const UINT8 *dest_key)
{
    if (dest_key == NULL) return;
    int n = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_connections);
    CONNECTION_INFO **conn_ptr = &connection_list;
    while (*conn_ptr != NULL)
    {
        // TCP-only: callers are the TCP FIN/RST paths; never evict a UDP
        // entry that happens to share the port number. Removal follows the
        // full key so a sibling entry (same port, other destination) and any
        // same-port UDP entry survive.
        if ((*conn_ptr)->src_port == src_port && !(*conn_ptr)->is_udp &&
            (*conn_ptr)->family == family &&
            memcmp((*conn_ptr)->orig_dest_addr, dest_key, n) == 0)
        {
            CONNECTION_INFO *to_free = *conn_ptr;
            *conn_ptr = to_free->next;
            free(to_free);
            break;
        }
        conn_ptr = &(*conn_ptr)->next;
    }
    LeaveCriticalSection(&lock_connections);
}

void clear_connections()
{
    EnterCriticalSection(&lock_connections);
    while (connection_list != NULL)
    {
        CONNECTION_INFO *to_free = connection_list;
        connection_list = connection_list->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_connections);
}

// === Logged Connections ===
// (protected by lock_logged)

// Hard cap on the dedup list. Pruning is TTL-driven; this cap is a safety net
// so a burst of new unique connections between cleanup cycles can never grow
// the list without bound (which would also make the O(n) lookup slower).
#define LOGGED_CONNECTIONS_MAX 1024

// Remove the oldest (tail) entries until the list is within the cap.
// Caller must hold lock_logged.
static void trim_logged_connections(void)
{
    UINT32 count = 0;
    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL) {
        count++;
        logged = logged->next;
    }

    while (count > LOGGED_CONNECTIONS_MAX) {
        LOGGED_CONNECTION *prev = NULL;
        LOGGED_CONNECTION *curr = logged_connections;
        while (curr->next != NULL) {
            prev = curr;
            curr = curr->next;
        }
        // curr is the tail (oldest entry)
        if (prev != NULL) {
            prev->next = NULL;
        } else {
            logged_connections = NULL;
        }
        free(curr);
        count--;
    }
}

// Remove entries older than ttl_ms. Unsigned subtraction handles the
// GetTickCount() wraparound case automatically: (now - ts) is correct
// modulo 2^32, so (now - ts) > ttl is a safe age test.
void prune_logged_connections(DWORD now_ms, DWORD ttl_ms)
{
    EnterCriticalSection(&lock_logged);
    LOGGED_CONNECTION **logged_ptr = &logged_connections;
    while (*logged_ptr != NULL) {
        LOGGED_CONNECTION *logged = *logged_ptr;
        if ((now_ms - logged->timestamp) > ttl_ms) {
            *logged_ptr = logged->next;
            free(logged);
        } else {
            logged_ptr = &logged->next;
        }
    }
    LeaveCriticalSection(&lock_logged);
}

BOOL is_connection_already_logged(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action)
{
    BOOL found = FALSE;
    EnterCriticalSection(&lock_logged);
    LOGGED_CONNECTION *logged = logged_connections;
    while (logged != NULL)
    {
        if (logged->pid == pid &&
            logged->family == family &&
            memcmp(logged->dest_addr, dest_addr, 16) == 0 &&
            logged->dest_port == dest_port &&
            logged->action == action)
        {
            found = TRUE;
            break;
        }
        logged = logged->next;
    }
    LeaveCriticalSection(&lock_logged);
    return found;
}

void add_logged_connection(DWORD pid, int family, const UINT8 *dest_addr, UINT16 dest_port, RuleAction action)
{
    EnterCriticalSection(&lock_logged);
    LOGGED_CONNECTION *logged = (LOGGED_CONNECTION *)malloc(sizeof(LOGGED_CONNECTION));
    if (logged != NULL)
    {
        logged->pid = pid;
        logged->family = family;
        memcpy(logged->dest_addr, dest_addr, 16);
        logged->dest_port = dest_port;
        logged->action = action;
        logged->timestamp = GetTickCount();
        logged->next = logged_connections;
        logged_connections = logged;
        trim_logged_connections();
    }
    LeaveCriticalSection(&lock_logged);
}

void clear_logged_connections()
{
    EnterCriticalSection(&lock_logged);
    while (logged_connections != NULL)
    {
        LOGGED_CONNECTION *to_free = logged_connections;
        logged_connections = logged_connections->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_logged);
}

// === Proxy Configs ===
// (protected by lock_proxies; get_proxy_by_id assumes the caller holds it)

PROXY_CONFIG* get_proxy_by_id(UINT32 proxy_id)
{
    // IMPORTANT: the caller MUST hold lock_proxies. This function only walks
    // the list; it never locks itself, because several callers need the
    // returned pointer only briefly while other callers make a stack copy.
    
    PROXY_CONFIG *config = proxy_configs;
    while (config != NULL)
    {
        if (config->proxy_id == proxy_id)
        {
            return config;
        }
        config = config->next;
    }
    return NULL;
}

void clear_proxy_configs()
{
    EnterCriticalSection(&lock_proxies);
    while (proxy_configs != NULL)
    {
        PROXY_CONFIG *to_free = proxy_configs;
        proxy_configs = proxy_configs->next;
        free(to_free);
    }
    LeaveCriticalSection(&lock_proxies);
}

// === UDP Associations ===
// (protected by lock_udp)

void add_udp_association(UDP_ASSOCIATION* assoc)
{
    EnterCriticalSection(&lock_udp);
    assoc->next = udp_associations;
    udp_associations = assoc;
    LeaveCriticalSection(&lock_udp);
}

void clear_udp_associations()
{
    EnterCriticalSection(&lock_udp);
    while (udp_associations != NULL)
    {
        UDP_ASSOCIATION *to_free = udp_associations;
        udp_associations = to_free->next;
        closesocket(to_free->control_socket);
        closesocket(to_free->udp_socket);
        free(to_free);
    }
    LeaveCriticalSection(&lock_udp);
}
