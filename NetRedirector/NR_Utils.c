// --- FILE: NR_Utils.c ---
#include "NR_Utils.h"
#include <ws2tcpip.h> // [Added] for getaddrinfo

// === PID Lookup Caches ===
//
// get_process_id_from_*() call GetExtendedTcpTable / GetExtendedUdpTable, which
// enumerate the ENTIRE system connection table. On an active machine that is a
// sizeable kernel+user-space cost when it happens for every new connection.
//
// Two complementary caches reduce the cost:
//   1. PID_RESULT_CACHE  : (family, local ip, local port, is_udp) -> pid
//      UDP sockets are long-lived and reused for many destinations, so a single
//      socket only needs ONE table scan per TTL window instead of one per
//      packet/flow. TCP port reuse (TIME_WAIT recycling, SYN retransmits) also
//      benefits. A cache MISS always falls through to a fresh table scan, so a
//      brand-new connection can never be "lost" to a stale snapshot.
//   2. PROCESS_NAME_CACHE: pid -> full process path. Eliminates the
//      OpenProcess + QueryFullProcessImageNameA syscall pair for subsequent
//      connections opened by the same process (browsers/games open hundreds).
//
// Both are guarded by lock_pid_cache. They are only touched on the "new
// connection" path (not per steady-state packet), so lock contention is
// negligible. Entries expire via TTL (GetTickCount, wraps safely with unsigned
// math) and are fully cleared by clear_pid_cache() on NetRedirector_Stop.

#define PID_RESULT_CACHE_SIZE 128
#define PID_RESULT_CACHE_TTL_TCP_MS 1500
#define PID_RESULT_CACHE_TTL_UDP_MS 5000

typedef struct {
    DWORD timestamp;
    int family;               // AF_INET or AF_INET6
    BOOL is_udp;
    UINT8 local_addr[16];     // network byte order (IPv4 uses first 4 bytes)
    UINT16 local_port;        // host byte order
    DWORD pid;
} PID_RESULT_CACHE_ENTRY;

static PID_RESULT_CACHE_ENTRY g_pid_result_cache[PID_RESULT_CACHE_SIZE];
static UINT32 g_pid_cache_next_slot = 0;   // round-robin replacement

#define PROCESS_NAME_CACHE_SIZE 64
#define PROCESS_NAME_CACHE_TTL_MS 5000

typedef struct {
    DWORD pid;
    DWORD timestamp;
    char name[MAX_PROCESS_NAME];
} PROCESS_NAME_CACHE_ENTRY;

static PROCESS_NAME_CACHE_ENTRY g_process_name_cache[PROCESS_NAME_CACHE_SIZE];

// Look up a cached pid result. Returns 0 on miss/expired.
static DWORD pid_result_cache_lookup(int family, BOOL is_udp, const UINT8 *local_addr, UINT16 local_port)
{
    DWORD now = GetTickCount();
    DWORD ttl = is_udp ? PID_RESULT_CACHE_TTL_UDP_MS : PID_RESULT_CACHE_TTL_TCP_MS;
    int addr_len = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < PID_RESULT_CACHE_SIZE; i++) {
        PID_RESULT_CACHE_ENTRY *e = &g_pid_result_cache[i];
        if (e->pid == 0) continue;
        if (e->family != family || e->is_udp != is_udp || e->local_port != local_port) continue;
        if ((now - e->timestamp) > ttl) continue;
        if (memcmp(e->local_addr, local_addr, addr_len) != 0) continue;
        LeaveCriticalSection(&lock_pid_cache);
        return e->pid;
    }
    LeaveCriticalSection(&lock_pid_cache);
    return 0;
}

// Store a pid result. Refreshes an existing entry for the same socket, else
// replaces the next round-robin slot. Failures (pid == 0) are NOT cached so a
// transient miss always retries a real table scan.
static void pid_result_cache_store(int family, BOOL is_udp, const UINT8 *local_addr, UINT16 local_port, DWORD pid)
{
    if (pid == 0) return;
    int addr_len = (family == AF_INET) ? 4 : 16;

    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < PID_RESULT_CACHE_SIZE; i++) {
        PID_RESULT_CACHE_ENTRY *e = &g_pid_result_cache[i];
        if (e->pid == 0) continue;
        if (e->family == family && e->is_udp == is_udp && e->local_port == local_port &&
            memcmp(e->local_addr, local_addr, addr_len) == 0) {
            e->timestamp = GetTickCount();
            e->pid = pid;
            LeaveCriticalSection(&lock_pid_cache);
            return;
        }
    }
    PID_RESULT_CACHE_ENTRY *slot = &g_pid_result_cache[g_pid_cache_next_slot++ % PID_RESULT_CACHE_SIZE];
    slot->timestamp = GetTickCount();
    slot->family = family;
    slot->is_udp = is_udp;
    memset(slot->local_addr, 0, sizeof(slot->local_addr));
    memcpy(slot->local_addr, local_addr, addr_len);
    slot->local_port = local_port;
    slot->pid = pid;
    LeaveCriticalSection(&lock_pid_cache);
}

void clear_pid_cache(void)
{
    EnterCriticalSection(&lock_pid_cache);
    memset(g_pid_result_cache, 0, sizeof(g_pid_result_cache));
    memset(g_process_name_cache, 0, sizeof(g_process_name_cache));
    g_pid_cache_next_slot = 0;
    LeaveCriticalSection(&lock_pid_cache);
}

// [Preserved] Original parse_ipv4 (as auxiliary for resolve_hostname)
UINT32 parse_ipv4(const char *ip)
{
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255)
        return 0;
    return (a << 0) | (b << 8) | (c << 16) | (d << 24);
}

// [Added] From : Support for domain name resolution
UINT32 resolve_hostname(const char *hostname)
{
    if (hostname == NULL || hostname[0] == '\0')
        return 0;

    // 1. First try to parse as pure IP
    UINT32 ip = parse_ipv4(hostname);
    if (ip != 0) return ip;

    // 2. If not IP, try DNS resolution
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // Only take IPv4
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        log_message("Failed to resolve hostname: %s", hostname);
        return 0;
    }

    if (result == NULL || result->ai_family != AF_INET) {
        if (result != NULL) freeaddrinfo(result);
        log_message("No IPv4 address found for hostname: %s", hostname);
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    UINT32 resolved_ip = addr->sin_addr.s_addr;
    freeaddrinfo(result);

    // log_message("Resolved %s to %u.%u.%u.%u", hostname, ...); // Optional: Enable logging
    return resolved_ip;
}

// [Added] IPv6 hostname resolution (mirror of resolve_hostname for AF_INET6).
// Returns TRUE and writes 16 bytes (network byte order) into out_addr6 on
// success. getaddrinfo() with AF_INET6 also parses literal IPv6 addresses, so
// no separate literal-parse step is needed (unlike the IPv4 dotted-quad case).
BOOL resolve_hostname6(const char *hostname, UINT8 *out_addr6)
{
    if (hostname == NULL || hostname[0] == '\0' || out_addr6 == NULL)
        return FALSE;

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        return FALSE;
    }

    BOOL ok = FALSE;
    for (struct addrinfo *p = result; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET6) {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)p->ai_addr;
            memcpy(out_addr6, &sa->sin6_addr, 16);
            ok = TRUE;
            break;
        }
    }
    freeaddrinfo(result);
    return ok;
}

// === DNS Resolution Cache (for domain-name rules) ===
//
// Hosts field now supports domain names ("google.com" / "*.google.com"). The
// packet engine only has the destination IP, so the rule's hostname must be
// resolved to an IP first. A cache prevents getaddrinfo() on every new
// connection:
//   1. Cache hit + not expired   -> return cached IP (O(1))
//   2. miss / expired            -> getaddrinfo() + round-robin store
// TTL expiry triggers re-resolution; DNS changes take effect within 1 minute
// ("periodic re-resolution"). Resolution failures (ip == 0) are cached too,
// so an unresolvable domain does not hammer the resolver.
// Shares lock_pid_cache with the PID caches. Cleared by clear_dns_cache() on
// NetRedirector_Stop.

#define DNS_CACHE_SIZE 64
#define DNS_CACHE_TTL_MS 60000   // 1 minute

typedef struct {
    DWORD timestamp;
    char domain[256];
    UINT32 ip;           // resolved IP (network byte order); 0 = failure
} DNS_CACHE_ENTRY;

static DNS_CACHE_ENTRY g_dns_cache[DNS_CACHE_SIZE];
static UINT32 g_dns_cache_next_slot = 0;   // round-robin replacement

// IPv6 flavor of the rule-DNS cache (parallel to the IPv4 cache above). Same
// TTL and slot-reuse policy. `valid == FALSE` records a cached failure (a
// domain with no AAAA record), so an unresolvable domain does not hammer the
// resolver — mirroring the IPv4 "ip == 0" convention.
typedef struct {
    DWORD timestamp;
    char domain[256];
    UINT8 addr[16];   // resolved IPv6 (network byte order); meaningful when valid
    BOOL valid;       // FALSE = cached failure (domain set but no AAAA)
} DNS_CACHE_ENTRY6;

static DNS_CACHE_ENTRY6 g_dns_cache6[DNS_CACHE_SIZE];
static UINT32 g_dns_cache6_next_slot = 0;   // round-robin replacement

UINT32 resolve_rule_host(const char *host)
{
    if (host == NULL || host[0] == '\0') return 0;

    DWORD now = GetTickCount();

    // 1. Cache lookup (TTL-based expiry, mirrors pid_result_cache_lookup)
    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < DNS_CACHE_SIZE; i++) {
        DNS_CACHE_ENTRY *e = &g_dns_cache[i];
        if (e->domain[0] == '\0') continue;
        if (strcmp(e->domain, host) != 0) continue;
        if ((now - e->timestamp) > DNS_CACHE_TTL_MS) continue;  // expired -> treat as miss
        UINT32 ip = e->ip;
        LeaveCriticalSection(&lock_pid_cache);
        return ip;
    }
    LeaveCriticalSection(&lock_pid_cache);

    // 2. Miss: resolve through the OS resolver (resolve_hostname also handles
    //    the case where the "host" is actually a literal IP), then cache it.
    UINT32 ip = resolve_hostname(host);

    EnterCriticalSection(&lock_pid_cache);
    DNS_CACHE_ENTRY *slot = &g_dns_cache[g_dns_cache_next_slot++ % DNS_CACHE_SIZE];
    slot->timestamp = now;
    strncpy(slot->domain, host, sizeof(slot->domain) - 1);
    slot->domain[sizeof(slot->domain) - 1] = '\0';
    slot->ip = ip;
    LeaveCriticalSection(&lock_pid_cache);

    return ip;
}

// [Added] Cache-only lookup for the packet-thread match path. getaddrinfo()
// can block for seconds (no timeout control); calling it from a packet
// processor while it holds lock_rules would stall every other packet thread
// and the rule APIs, and with the WinDivert queue time at 2000 ms this means
// machine-wide packet loss whenever DNS is slow. The match path therefore
// only reads the cache (stale entries are used rather than dropping the rule
// - stale-while-revalidate); the background refresher thread keeps the cache
// warm via force_resolve_rule_host().
UINT32 resolve_rule_host_cached(const char *host)
{
    if (host == NULL || host[0] == '\0') return 0;

    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < DNS_CACHE_SIZE; i++) {
        DNS_CACHE_ENTRY *e = &g_dns_cache[i];
        if (e->domain[0] == '\0') continue;
        if (strcmp(e->domain, host) != 0) continue;
        UINT32 ip = e->ip;
        LeaveCriticalSection(&lock_pid_cache);
        return ip;
    }
    LeaveCriticalSection(&lock_pid_cache);
    return 0;
}

// [Added] Unconditional resolve + store for the background refresher. Unlike
// resolve_rule_host this never reads the cache first, so periodic refreshes
// actually re-resolve and DNS changes propagate within one refresh cycle.
void force_resolve_rule_host(const char *host)
{
    if (host == NULL || host[0] == '\0') return;

    UINT32 ip = resolve_hostname(host);

    EnterCriticalSection(&lock_pid_cache);
    // Refresh in place when the domain already has a slot (keeps the cache
    // dense instead of round-robin-evicting ourselves every cycle).
    DNS_CACHE_ENTRY *slot = NULL;
    for (UINT32 i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_dns_cache[i].domain[0] != '\0' && strcmp(g_dns_cache[i].domain, host) == 0) {
            slot = &g_dns_cache[i];
            break;
        }
    }
    if (slot == NULL) {
        slot = &g_dns_cache[g_dns_cache_next_slot++ % DNS_CACHE_SIZE];
        strncpy(slot->domain, host, sizeof(slot->domain) - 1);
        slot->domain[sizeof(slot->domain) - 1] = '\0';
    }
    slot->timestamp = GetTickCount();
    slot->ip = ip;
    LeaveCriticalSection(&lock_pid_cache);
}

// IPv6 cache-only lookup for the packet-thread match path (mirror of
// resolve_rule_host_cached). Never calls getaddrinfo — a cache miss returns
// FALSE (the background refresher fills the cache shortly after a rule is
// added/edited). A cached failure also returns FALSE.
BOOL resolve_rule_host_cached6(const char *host, UINT8 *out_addr6)
{
    if (host == NULL || host[0] == '\0' || out_addr6 == NULL) return FALSE;

    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < DNS_CACHE_SIZE; i++) {
        DNS_CACHE_ENTRY6 *e = &g_dns_cache6[i];
        if (e->domain[0] == '\0') continue;
        if (strcmp(e->domain, host) != 0) continue;
        BOOL ok = e->valid;
        if (ok) memcpy(out_addr6, e->addr, 16);
        LeaveCriticalSection(&lock_pid_cache);
        return ok;
    }
    LeaveCriticalSection(&lock_pid_cache);
    return FALSE;
}

// IPv6 unconditional resolve + store for the background refresher (mirror of
// force_resolve_rule_host).
void force_resolve_rule_host6(const char *host)
{
    if (host == NULL || host[0] == '\0') return;

    UINT8 addr[16];
    BOOL valid = resolve_hostname6(host, addr);

    EnterCriticalSection(&lock_pid_cache);
    DNS_CACHE_ENTRY6 *slot = NULL;
    for (UINT32 i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_dns_cache6[i].domain[0] != '\0' && strcmp(g_dns_cache6[i].domain, host) == 0) {
            slot = &g_dns_cache6[i];
            break;
        }
    }
    if (slot == NULL) {
        slot = &g_dns_cache6[g_dns_cache6_next_slot++ % DNS_CACHE_SIZE];
        strncpy(slot->domain, host, sizeof(slot->domain) - 1);
        slot->domain[sizeof(slot->domain) - 1] = '\0';
    }
    slot->timestamp = GetTickCount();
    slot->valid = valid;
    if (valid) memcpy(slot->addr, addr, 16);
    LeaveCriticalSection(&lock_pid_cache);
}

void clear_dns_cache(void)
{
    EnterCriticalSection(&lock_pid_cache);
    memset(g_dns_cache, 0, sizeof(g_dns_cache));
    g_dns_cache_next_slot = 0;
    memset(g_dns_cache6, 0, sizeof(g_dns_cache6));
    g_dns_cache6_next_slot = 0;
    LeaveCriticalSection(&lock_pid_cache);
}

// === DNS Snooping: IP -> domain reverse map ===
//
// Wildcard domain rules ("*.google.com") must match ANY subdomain, but the
// packet engine only ever sees the destination IP. This cache reverse-maps an
// IP to the domain names that recently resolved to it, by passively observing
// plaintext DNS responses (UDP source port 53) on the wire.
//
// Populated on the packet path (DNS responses are low-frequency) and read on
// the new-connection match path (cold path, never per-packet). A fixed TTL is
// used (v1 does not parse the per-record DNS TTL); expired entries fall back
// to the apex-resolve path in match_ip_pattern. Guarded by lock_pid_cache,
// same as the rule-DNS cache above (both acquisitions are short).
//
// Limitation: only plaintext DNS is observable. DoH/DoT (443/853) and DNS that
// is itself routed through a proxy are invisible here, so wildcard-subdomain
// rules then degrade to apex-only matching.

#define DNS_SNOOP_CACHE_SIZE 512
#define DNS_SNOOP_TTL_MS 600000   // 10 minutes
#define DNS_SNOOP_MAX_DOMAINS 4   // per-IP domain list cap (CDN IP sharing)

typedef struct {
    DWORD timestamp;
    int family;               // AF_INET or AF_INET6
    UINT8 addr[16];           // network byte order (IPv4 uses first 4 bytes)
    char domains[DNS_SNOOP_MAX_DOMAINS][256];
    int domain_count;
} DNS_SNOOP_ENTRY;

static DNS_SNOOP_ENTRY g_dns_snoop_cache[DNS_SNOOP_CACHE_SIZE];
static UINT32 g_dns_snoop_next_slot = 0;

// Maximum compression-pointer hops before declaring a name malformed
// (defends against pointer loops in hostile/malformed packets).
#define DNS_MAX_POINTER_HOPS 16

// Decode a DNS name starting at message offset `off`, following compression
// pointers. Writes the dotted form into `out` (bounded, NULL-terminated).
// Returns TRUE on success. Does not touch the caller's position.
static BOOL dns_decode_name(const UINT8 *msg, UINT msg_len, UINT off, char *out, UINT out_len)
{
    UINT hops = 0;
    UINT pos = off;
    UINT out_pos = 0;
    BOOL first = TRUE;

    if (out == NULL || out_len == 0) return FALSE;
    out[0] = '\0';

    while (hops < DNS_MAX_POINTER_HOPS) {
        if (pos >= msg_len) return FALSE;
        UINT8 len = msg[pos];

        if ((len & 0xC0) == 0xC0) {
            // Compression pointer: two bytes, target is an offset from msg[0].
            if (pos + 1 >= msg_len) return FALSE;
            UINT target = ((UINT)(len & 0x3F) << 8) | msg[pos + 1];
            if (target >= msg_len) return FALSE;
            pos = target;
            hops++;
            continue;
        }
        if ((len & 0xC0) != 0) return FALSE;  // reserved label type (0x40/0x80)

        pos++;                       // move past the length byte
        if (len == 0) break;         // root label: end of name

        if (pos + len > msg_len) return FALSE;

        if (!first) {
            if (out_pos + 1 >= out_len) return FALSE;
            out[out_pos++] = '.';
        }
        first = FALSE;

        if (out_pos + len >= out_len) return FALSE;
        memcpy(out + out_pos, msg + pos, len);
        out_pos += len;
        pos += len;
    }

    if (hops >= DNS_MAX_POINTER_HOPS) return FALSE;
    out[out_pos] = '\0';
    return TRUE;
}

// Advance *pos past a DNS name in the message. A compression pointer advances
// by exactly 2 bytes (it terminates the name at the pointer site). Used to
// skip question/answer names without decoding them.
static BOOL dns_skip_name(const UINT8 *msg, UINT msg_len, UINT *pos)
{
    while (*pos < msg_len) {
        UINT8 len = msg[*pos];
        if ((len & 0xC0) == 0xC0) {
            if (*pos + 1 >= msg_len) return FALSE;
            *pos += 2;
            return TRUE;
        }
        if ((len & 0xC0) != 0) return FALSE;
        (*pos)++;
        if (len == 0) return TRUE;
        if (*pos + len > msg_len) return FALSE;
        *pos += len;
    }
    return FALSE;
}

// Record one address -> domain mapping (append to an existing entry, else a
// fresh round-robin slot). No-ops on empty domain. The entry is keyed by
// (family, addr), so the same cache serves IPv4 A records and IPv6 AAAA records.
static void dns_snoop_record_addr(int family, const UINT8 *addr, const char *domain)
{
    if (domain == NULL || domain[0] == '\0' || addr == NULL) return;

    int addr_len = (family == AF_INET) ? 4 : 16;
    DWORD now = GetTickCount();
    EnterCriticalSection(&lock_pid_cache);

    for (UINT32 i = 0; i < DNS_SNOOP_CACHE_SIZE; i++) {
        DNS_SNOOP_ENTRY *e = &g_dns_snoop_cache[i];
        if (e->family != family) continue;
        if (memcmp(e->addr, addr, addr_len) != 0) continue;

        // Dedup, then append if there is room.
        int d;
        for (d = 0; d < e->domain_count; d++) {
            if (strcmp(e->domains[d], domain) == 0) break;
        }
        if (d == e->domain_count && e->domain_count < DNS_SNOOP_MAX_DOMAINS) {
            strncpy(e->domains[e->domain_count], domain, sizeof(e->domains[0]) - 1);
            e->domains[e->domain_count][sizeof(e->domains[0]) - 1] = '\0';
            e->domain_count++;
        }
        e->timestamp = now;
        LeaveCriticalSection(&lock_pid_cache);
        return;
    }

    DNS_SNOOP_ENTRY *slot = &g_dns_snoop_cache[g_dns_snoop_next_slot++ % DNS_SNOOP_CACHE_SIZE];
    memset(slot, 0, sizeof(*slot));
    slot->family = family;
    memcpy(slot->addr, addr, addr_len);
    slot->timestamp = now;
    slot->domain_count = 1;
    strncpy(slot->domains[0], domain, sizeof(slot->domains[0]) - 1);
    slot->domains[0][sizeof(slot->domains[0]) - 1] = '\0';

    LeaveCriticalSection(&lock_pid_cache);
}

// IPv4 wrapper (A record): the UINT32 is in network byte order, matching
// parse_ipv4 / *(UINT32*)dest_addr.
void dns_snoop_record(UINT32 ip, const char *domain)
{
    if (ip == 0) return;
    UINT8 a[16];
    memset(a, 0, sizeof(a));
    memcpy(a, &ip, 4);
    dns_snoop_record_addr(AF_INET, a, domain);
}

// IPv6 wrapper (AAAA record).
void dns_snoop_record6(const UINT8 *addr6, const char *domain)
{
    dns_snoop_record_addr(AF_INET6, addr6, domain);
}

// Query the snoop cache: does the address map to a domain equal to `suffix` or
// ending in ".suffix"? Cache-only and bounded — safe on the packet thread.
static BOOL dns_snoop_matches_suffix_addr(int family, const UINT8 *addr, const char *suffix)
{
    if (suffix == NULL || suffix[0] == '\0' || addr == NULL) return FALSE;

    int addr_len = (family == AF_INET) ? 4 : 16;
    size_t suffix_len = strlen(suffix);
    DWORD now = GetTickCount();

    EnterCriticalSection(&lock_pid_cache);
    for (UINT32 i = 0; i < DNS_SNOOP_CACHE_SIZE; i++) {
        DNS_SNOOP_ENTRY *e = &g_dns_snoop_cache[i];
        if (e->family != family) continue;
        if (memcmp(e->addr, addr, addr_len) != 0) continue;
        if ((now - e->timestamp) > DNS_SNOOP_TTL_MS) continue;  // expired

        for (int d = 0; d < e->domain_count; d++) {
            const char *dom = e->domains[d];
            size_t dom_len = strlen(dom);
            if (dom_len == suffix_len && _stricmp(dom, suffix) == 0) {
                LeaveCriticalSection(&lock_pid_cache);
                return TRUE;
            }
            if (dom_len > suffix_len && dom[dom_len - suffix_len - 1] == '.' &&
                _stricmp(dom + dom_len - suffix_len, suffix) == 0) {
                LeaveCriticalSection(&lock_pid_cache);
                return TRUE;
            }
        }
        break;  // at most one entry per (family, addr)
    }
    LeaveCriticalSection(&lock_pid_cache);
    return FALSE;
}

// IPv4 wrapper.
BOOL dns_snoop_matches_suffix(UINT32 ip, const char *suffix)
{
    UINT8 a[16];
    memset(a, 0, sizeof(a));
    memcpy(a, &ip, 4);
    return dns_snoop_matches_suffix_addr(AF_INET, a, suffix);
}

// IPv6 wrapper.
BOOL dns_snoop_matches_suffix6(const UINT8 *addr6, const char *suffix)
{
    return dns_snoop_matches_suffix_addr(AF_INET6, addr6, suffix);
}

// Parse a plaintext DNS response message and record every A record's IP under
// the question name. Returns the number of A records processed, or -1 if the
// message is not a parseable DNS response (or not a response at all).
int dns_snoop_parse_response(const UINT8 *msg, UINT msg_len)
{
    if (msg == NULL || msg_len < 12) return -1;

    UINT16 flags = ((UINT16)msg[2] << 8) | msg[3];
    BOOL is_response = (flags & 0x8000) != 0;
    UINT16 qdcount = ((UINT16)msg[4] << 8) | msg[5];
    UINT16 ancount = ((UINT16)msg[6] << 8) | msg[7];

    if (!is_response || qdcount == 0) return -1;

    // Decode the first question name (the domain the app was resolving).
    char domain[256];
    if (!dns_decode_name(msg, msg_len, 12, domain, sizeof(domain))) return -1;

    // Skip the question section: QNAME(s) + QTYPE(2) + QCLASS(2) each.
    UINT pos = 12;
    UINT16 q;
    for (q = 0; q < qdcount; q++) {
        if (!dns_skip_name(msg, msg_len, &pos)) return -1;
        pos += 4;
    }

    int recorded = 0;
    UINT16 a;
    for (a = 0; a < ancount; a++) {
        if (!dns_skip_name(msg, msg_len, &pos)) return -1;   // answer NAME
        if (pos + 10 > msg_len) return -1;                   // TYPE+CLASS+TTL+RDLENGTH
        UINT16 type = ((UINT16)msg[pos] << 8) | msg[pos + 1];
        UINT16 rdlength = ((UINT16)msg[pos + 8] << 8) | msg[pos + 9];
        pos += 10;
        if (pos + rdlength > msg_len) return -1;

        if (type == 1 && rdlength == 4) {
            // A record: 4-byte IPv4 in network byte order. Read as a UINT32 so
            // the stored value matches the packet-engine convention used by
            // parse_ipv4 / *(UINT32*)dest_addr (e.g. 1.2.3.4 -> 0x04030201).
            UINT32 ip;
            memcpy(&ip, msg + pos, 4);
            dns_snoop_record(ip, domain);
            recorded++;
        }
        else if (type == 28 && rdlength == 16) {
            // AAAA record: 16-byte IPv6 in network byte order.
            dns_snoop_record6(msg + pos, domain);
            recorded++;
        }
        pos += rdlength;
    }
    return recorded;
}

// Clear the DNS snoop cache (called on Stop alongside clear_dns_cache).
void clear_dns_snoop_cache(void)
{
    EnterCriticalSection(&lock_pid_cache);
    memset(g_dns_snoop_cache, 0, sizeof(g_dns_snoop_cache));
    g_dns_snoop_next_slot = 0;
    LeaveCriticalSection(&lock_pid_cache);
}

// [Added] Pre-resolve every domain pattern inside one rule's hosts field
// ("a.com;8.8.8.8;*.b.com" -> force-resolve a.com and b.com). Called by the
// background DNS refresher thread only - never from a packet thread. Skips
// wildcards and IP-octet patterns, mirrors the "*." stripping done by
// match_ip_pattern so both sides resolve the identical host string.
void refresh_rule_dns(const char *hosts_field)
{
    if (hosts_field == NULL || hosts_field[0] == '\0' || is_wildcard_str(hosts_field)) return;

    size_t len = strlen(hosts_field) + 1;
    char *copy = malloc(len);
    if (copy == NULL) return;
    strncpy(copy, hosts_field, len);

    char *token = strtok(copy, ";");
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;
        if (token[0] != '\0' && !is_wildcard_str(token) && !is_ip_like_pattern(token)) {
            if (token[0] == '*' && token[1] == '.') token += 2;
            if (token[0] != '\0') {
                force_resolve_rule_host(token);
                force_resolve_rule_host6(token);
            }
        }
        token = strtok(NULL, ";");
    }
    free(copy);
}

// [Preserved] Helper function
const char* extract_filename(const char* path)
{
    if (!path) return "";
    const char* last_backslash = strrchr(path, '\\');
    const char* last_slash = strrchr(path, '/');
    const char* last_separator = (last_backslash > last_slash) ? last_backslash : last_slash;
    return last_separator ? (last_separator + 1) : path;
}

// [Preserved] KeepAlive and Base64
void EnableKeepAlive(SOCKET s) {
    if (s == INVALID_SOCKET) return;
    BOOL bKeepAlive = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&bKeepAlive, sizeof(bKeepAlive));
    struct tcp_keepalive alive_in = { 0 };
    alive_in.onoff = 1;
    alive_in.keepalivetime = 20000;
    alive_in.keepaliveinterval = 3000;
    DWORD dwBytesRet = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), NULL, 0, &dwBytesRet, NULL, NULL);
}

// [Added] Bounded connect(): switches the socket to non-blocking, starts the
// connect, waits up to timeout_ms via select(), then restores blocking mode.
// A plain blocking connect() stalls ~21 s (TCP SYN retries) per attempt on a
// dead proxy; with thread-per-connection those stalled threads pile up.
// Returns TRUE when connected, FALSE on failure/timeout (socket left in
// blocking mode either way; caller decides whether to close it).
BOOL connect_with_timeout(SOCKET s, const struct sockaddr *addr, int addrlen, DWORD timeout_ms)
{
    u_long non_blocking = 1;
    u_long blocking = 0;
    if (ioctlsocket(s, FIONBIO, &non_blocking) == SOCKET_ERROR) return FALSE;

    BOOL connected = FALSE;
    int rc = connect(s, addr, addrlen);
    if (rc == 0) {
        connected = TRUE;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set write_fds, except_fds;
        FD_ZERO(&write_fds); FD_SET(s, &write_fds);
        FD_ZERO(&except_fds); FD_SET(s, &except_fds);
        struct timeval tv = { (long)(timeout_ms / 1000), (long)((timeout_ms % 1000) * 1000) };
        if (select(0, NULL, &write_fds, &except_fds, &tv) > 0) {
            if (FD_ISSET(s, &except_fds)) {
                connected = FALSE;
            } else {
                int so_error = 0;
                int optlen = sizeof(so_error);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &optlen);
                connected = (so_error == 0);
            }
        }
    }

    ioctlsocket(s, FIONBIO, &blocking);
    return connected;
}

void base64_encode(const char* input, char* output, size_t output_size) {
    static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t input_len = strlen(input);
    size_t output_len = 0;
    for (size_t i = 0; i < input_len && output_len < output_size - 4; i += 3) {
        unsigned char b1 = input[i];
        unsigned char b2 = (i + 1 < input_len) ? input[i + 1] : 0;
        unsigned char b3 = (i + 2 < input_len) ? input[i + 2] : 0;
        output[output_len++] = base64_chars[b1 >> 2];
        output[output_len++] = base64_chars[((b1 & 0x03) << 4) | (b2 >> 4)];
        output[output_len++] = (i + 1 < input_len) ? base64_chars[((b2 & 0x0F) << 2) | (b3 >> 6)] : '=';
        output[output_len++] = (i + 2 < input_len) ? base64_chars[b3 & 0x3F] : '=';
    }
    output[output_len] = '\0';
}

// [Preserved] Process ID retrieval logic — now cache-first (see caches above)
DWORD get_process_id_from_connection(UINT32 src_ip, UINT16 src_port) {
    UINT8 addr4[4];
    memcpy(addr4, &src_ip, 4);
    DWORD cached = pid_result_cache_lookup(AF_INET, FALSE, addr4, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_TCPTABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    tcp_table = (MIB_TCPTABLE_OWNER_PID *)malloc(size);
    if (!tcp_table) return 0;
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID *row = &tcp_table->table[i];
            if (row->dwLocalAddr == src_ip && ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid; break;
            }
        }
    }
    free(tcp_table);
    pid_result_cache_store(AF_INET, FALSE, addr4, src_port, pid);
    return pid;
}

DWORD get_process_id_from_udp_connection(UINT32 src_ip, UINT16 src_port) {
    UINT8 addr4[4];
    memcpy(addr4, &src_ip, 4);
    DWORD cached = pid_result_cache_lookup(AF_INET, TRUE, addr4, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_UDPTABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    udp_table = (MIB_UDPTABLE_OWNER_PID *)malloc(size);
    if (!udp_table) return 0;
    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
            MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];
            if (row->dwLocalAddr == src_ip && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
        }
        if (pid == 0) { // Try 0.0.0.0 match
            for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *row = &udp_table->table[i];
                if (row->dwLocalAddr == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
            }
        }
    }
    free(udp_table);
    pid_result_cache_store(AF_INET, TRUE, addr4, src_port, pid);
    return pid;
}

// === IPv6 Process ID lookup ===
DWORD get_process_id_from_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    DWORD cached = pid_result_cache_lookup(AF_INET6, FALSE, src_ip6, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_TCP6TABLE_OWNER_PID *tcp_table = NULL;
    DWORD size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    tcp_table = (MIB_TCP6TABLE_OWNER_PID *)malloc(size);
    if (!tcp_table) return 0;
    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            MIB_TCP6ROW_OWNER_PID *row = &tcp_table->table[i];
            if (memcmp(row->ucLocalAddr, src_ip6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) {
                pid = row->dwOwningPid; break;
            }
        }
    }
    free(tcp_table);
    pid_result_cache_store(AF_INET6, FALSE, src_ip6, src_port, pid);
    return pid;
}

DWORD get_process_id_from_udp_connection6(const UINT8 *src_ip6, UINT16 src_port) {
    DWORD cached = pid_result_cache_lookup(AF_INET6, TRUE, src_ip6, src_port);
    if (cached != 0) return cached;

    DWORD pid = 0;
    MIB_UDP6TABLE_OWNER_PID *udp_table = NULL;
    DWORD size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return 0;
    udp_table = (MIB_UDP6TABLE_OWNER_PID *)malloc(size);
    if (!udp_table) return 0;
    if (GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
            MIB_UDP6ROW_OWNER_PID *row = &udp_table->table[i];
            if (memcmp(row->ucLocalAddr, src_ip6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
        }
        if (pid == 0) { // Try :: (unspecified) match
            const UINT8 zero6[16] = {0};
            for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID *row = &udp_table->table[i];
                if (memcmp(row->ucLocalAddr, zero6, 16) == 0 && ntohs((UINT16)row->dwLocalPort) == src_port) { pid = row->dwOwningPid; break; }
            }
        }
    }
    free(udp_table);
    pid_result_cache_store(AF_INET6, TRUE, src_ip6, src_port, pid);
    return pid;
}

// === IPv6 helpers ===

void addr_to_string(int family, const UINT8 *addr, char *buf, size_t size)
{
    if (buf == NULL || size == 0) return;
    if (family == AF_INET6) {
        if (inet_ntop(AF_INET6, addr, buf, (DWORD)size) == NULL)
            snprintf(buf, size, "::");
    } else {
        snprintf(buf, size, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    }
}

// Multicast (ff00::/8), link-local (fe80::/10), loopback (::1), unspecified (::)
BOOL is_multicast_or_special6(const UINT8 *a)
{
    if (a[0] == 0xFF) return TRUE;
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return TRUE;
    for (int i = 1; i < 16; i++) if (a[i] != 0) return FALSE;
    return (a[0] == 0x00 || a[0] == 0x01);
}

// --- LAN / On-link Detection ---
// Caches the local interface addresses (IPv4 + IPv6) and their prefix lengths.
// Used to auto-direct traffic that stays within the local network, so that
// LAN file transfers never get routed through an external proxy (e.g. a
// phone's SOCKS5 server going out over a 5G connection and back).

#define MAX_LOCAL_ADDRS 64

typedef struct LOCAL_ADDR {
    int family;              // AF_INET or AF_INET6
    UINT8 addr[16];          // Network byte order
    UINT8 prefix_len;
} LOCAL_ADDR;

static LOCAL_ADDR g_local_addrs[MAX_LOCAL_ADDRS];
static int g_local_addr_count = 0;

void refresh_local_addresses(void)
{
    ULONG size = 0;
    DWORD ret;
    PIP_ADAPTER_ADDRESSES adapters = NULL, cur;
    PIP_ADAPTER_UNICAST_ADDRESS unicast;

    g_local_addr_count = 0;

    // First call returns ERROR_BUFFER_OVERFLOW with the required size
    ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, NULL, &size);
    if (ret != ERROR_BUFFER_OVERFLOW || size == 0) return;

    adapters = (PIP_ADAPTER_ADDRESSES)malloc(size);
    if (adapters == NULL) return;

    ret = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        NULL, adapters, &size);
    if (ret != NO_ERROR) { free(adapters); return; }

    for (cur = adapters; cur != NULL && g_local_addr_count < MAX_LOCAL_ADDRS; cur = cur->Next) {
        if (cur->OperStatus != IfOperStatusUp) continue;
        if (cur->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;

        for (unicast = cur->FirstUnicastAddress; unicast != NULL; unicast = unicast->Next) {
            int family = unicast->Address.lpSockaddr->sa_family;
            UINT8 prefix = unicast->OnLinkPrefixLength;
            LOCAL_ADDR *slot = &g_local_addrs[g_local_addr_count];

            // Only trust realistic LAN prefixes; a /0 or /32-ish entry would
            // otherwise make everything (or nothing) look on-link.
            if (family == AF_INET) {
                if (prefix < 8 || prefix > 30) continue;
                struct sockaddr_in *sa = (struct sockaddr_in *)unicast->Address.lpSockaddr;
                slot->family = AF_INET;
                slot->prefix_len = prefix;
                memcpy(slot->addr, &sa->sin_addr, 4);
                g_local_addr_count++;
            } else if (family == AF_INET6) {
                if (prefix < 8 || prefix > 126) continue;
                struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)unicast->Address.lpSockaddr;
                slot->family = AF_INET6;
                slot->prefix_len = prefix;
                memcpy(slot->addr, &sa6->sin6_addr, 16);
                g_local_addr_count++;
            }
            if (g_local_addr_count >= MAX_LOCAL_ADDRS) break;
        }
    }
    free(adapters);
}

static void prefix_to_mask(UINT8 prefix, UINT8 *mask, int len)
{
    int full = prefix / 8;
    int rem = prefix % 8;
    memset(mask, 0, len);
    for (int i = 0; i < full && i < len; i++) mask[i] = 0xFF;
    if (full < len && rem > 0) mask[full] = (UINT8)(0xFF << (8 - rem));
}

BOOL is_lan_or_on_link_address(int family, const UINT8 *addr)
{
    if (addr == NULL) return FALSE;

    if (family == AF_INET) {
        // Private ranges (RFC 1918): 10/8, 172.16/12, 192.168/16
        if (addr[0] == 10) return TRUE;
        if (addr[0] == 172 && (addr[1] & 0xF0) == 16) return TRUE;
        if (addr[0] == 192 && addr[1] == 168) return TRUE;
    } else if (family == AF_INET6) {
        // Unique Local Address (RFC 4193): fc00::/7
        if ((addr[0] & 0xFE) == 0xFC) return TRUE;
    } else {
        return FALSE;
    }

    // On-link check: destination belongs to the same subnet as one of our
    // local addresses (covers global-scope IPv6 like 2001:b011:...:xxxx).
    for (int i = 0; i < g_local_addr_count; i++) {
        LOCAL_ADDR *local = &g_local_addrs[i];
        if (local->family != family) continue;

        UINT8 mask[16];
        prefix_to_mask(local->prefix_len, mask, (family == AF_INET) ? 4 : 16);
        int len = (family == AF_INET) ? 4 : 16;
        BOOL same = TRUE;
        for (int b = 0; b < len; b++) {
            if ((addr[b] & mask[b]) != (local->addr[b] & mask[b])) { same = FALSE; break; }
        }
        if (same) return TRUE;
    }
    return FALSE;
}

BOOL match_ip_pattern6(const char *pattern, const UINT8 *ip)
{
    if (is_wildcard_str(pattern)) return TRUE;

    // A domain rule never contains ':' (IPv6 literals always do).
    if (strchr(pattern, ':') == NULL) {
        BOOL is_subdomain_wildcard = (pattern[0] == '*' && pattern[1] == '.');
        const char *host = is_subdomain_wildcard ? pattern + 2 : pattern;

        // Wildcard subdomain: DNS-snoop reverse map first.
        if (is_subdomain_wildcard && dns_snoop_matches_suffix6(ip, host)) {
            return TRUE;
        }

        // Apex-resolution fallback (bare domain, and wildcard when the snoop
        // cache misses): compare against the IPv6 address resolved for `host`.
        UINT8 resolved[16];
        if (resolve_rule_host_cached6(host, resolved) &&
            memcmp(resolved, ip, 16) == 0) {
            return TRUE;
        }
        return FALSE;
    }

    char addr_str[MAX_IP_STR];
    addr_to_string(AF_INET6, ip, addr_str, sizeof(addr_str));
    return _stricmp(pattern, addr_str) == 0;
}

BOOL match_ip_list6(const char *ip_list, const UINT8 *ip)
{
    if (!ip_list || !ip_list[0] || is_wildcard_str(ip_list)) return TRUE;
    size_t len = strlen(ip_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, ip_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ";");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_ip_pattern6(token, ip)) { matched = TRUE; break; }
        token = strtok(NULL, ";");
    }
    free(copy); return matched;
}

BOOL get_process_name_from_pid(DWORD pid, char *name, DWORD name_size) {
    if (pid == 0 || name == NULL || name_size == 0) return FALSE;
    if (pid == 4) { strncpy(name, "System", name_size - 1); name[name_size - 1] = '\0'; return TRUE; } // Small improvement in : System process

    DWORD now = GetTickCount();

    // 1. Cache lookup (avoids OpenProcess + QueryFullProcessImageNameA per new connection)
    EnterCriticalSection(&lock_pid_cache);
    for (int i = 0; i < PROCESS_NAME_CACHE_SIZE; i++) {
        PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[i];
        if (e->pid == pid && e->name[0] && (now - e->timestamp) <= PROCESS_NAME_CACHE_TTL_MS) {
            strncpy(name, e->name, name_size - 1);
            name[name_size - 1] = '\0';
            LeaveCriticalSection(&lock_pid_cache);
            return TRUE;
        }
    }
    LeaveCriticalSection(&lock_pid_cache);

    // 2. Miss: query the system
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return FALSE;
    char full_path[MAX_PATH];
    DWORD path_len = MAX_PATH;
    BOOL ok = FALSE;
    if (QueryFullProcessImageNameA(hProcess, 0, full_path, &path_len)) {
        strncpy(name, full_path, name_size - 1);
        name[name_size - 1] = '\0';
        ok = TRUE;

        // 3. Store into cache: refresh the slot for this pid, else reuse the
        //    oldest/empty slot (simple LRU-ish replacement).
        EnterCriticalSection(&lock_pid_cache);
        int slot = -1;
        int oldest_slot = 0;
        DWORD oldest_ts = 0xFFFFFFFF;
        for (int i = 0; i < PROCESS_NAME_CACHE_SIZE; i++) {
            PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[i];
            if (e->pid == pid) { slot = i; break; }
            if (!e->name[0]) { slot = i; break; }
            if (e->timestamp < oldest_ts) { oldest_ts = e->timestamp; oldest_slot = i; }
        }
        if (slot < 0) slot = oldest_slot;
        PROCESS_NAME_CACHE_ENTRY *e = &g_process_name_cache[slot];
        e->pid = pid;
        e->timestamp = now;
        strncpy(e->name, full_path, MAX_PROCESS_NAME - 1);
        e->name[MAX_PROCESS_NAME - 1] = '\0';
        LeaveCriticalSection(&lock_pid_cache);
    }
    CloseHandle(hProcess);
    return ok;
}

// [Preserved] IP/Port Pattern matching logic
// [Modified] Domain-name rules: when the pattern is not a plain dotted IPv4
// (or per-octet-'*') form, treat it as a hostname, resolve it to an IP (with
// the DNS cache in resolve_rule_host) and compare with the packet destination.
static BOOL is_ip_like_pattern(const char *pattern)
{
    if (pattern == NULL || pattern[0] == '\0') return FALSE;
    const char *p = pattern;
    if (p[0] == '*' && p[1] == '.') p += 2;   // ignore leading "*.", e.g. "*.8.8.8.8" -> "8.8.8.8"
    int parts = 1;
    for (const char *q = p; *q != '\0'; q++) {
        char c = *q;
        if (c == '.') { parts++; continue; }
        if (c == '*' || (c >= '0' && c <= '9')) continue;
        return FALSE;   // contains a non-IP character (letters etc.) -> domain
    }
    return parts == 4;  // exactly 4 dot-separated parts -> keep the IP octet logic
}

BOOL match_ip_pattern(const char *pattern, UINT32 ip) {
    if (is_wildcard_str(pattern)) return TRUE;

    // [Added] Domain rules: "google.com" / "*.google.com". Strip a leading
    // "*." prefix before resolving ("*.google.com" -> "google.com"); the rule
    // matches when the resolved IP equals the packet destination IP.
    // [Modified] Uses the cache-only lookup: the packet thread must never
    // block in getaddrinfo(). A cache miss simply means "not resolved (yet)"
    // -> no match; the background refresher fills the cache shortly after a
    // rule is added/edited.
    if (!is_ip_like_pattern(pattern)) {
        // Domain rule. A leading "*." means "any subdomain": consult the
        // DNS-snoop reverse map first (with the apex-resolution path kept as
        // the fallback, and the sole path for bare domains).
        BOOL is_subdomain_wildcard = (pattern[0] == '*' && pattern[1] == '.');
        const char *host = is_subdomain_wildcard ? pattern + 2 : pattern;

        if (is_subdomain_wildcard && dns_snoop_matches_suffix(ip, host)) {
            return TRUE;
        }

        UINT32 resolved = resolve_rule_host_cached(host);
        return (resolved != 0 && resolved == ip);
    }

    unsigned char ip_octets[4];
    ip_octets[0] = (ip >> 0) & 0xFF; ip_octets[1] = (ip >> 8) & 0xFF;
    ip_octets[2] = (ip >> 16) & 0xFF; ip_octets[3] = (ip >> 24) & 0xFF;
    char pattern_copy[256]; strncpy(pattern_copy, pattern, sizeof(pattern_copy)-1); pattern_copy[255]='\0';
    char pattern_octets[4][16]; int octet_count=0, char_idx=0;
    for(int i=0; i<=(int)strlen(pattern_copy) && octet_count<4; i++) {
        if(pattern_copy[i]=='.'||pattern_copy[i]=='\0') {
            pattern_octets[octet_count][char_idx]='\0'; octet_count++; char_idx=0;
            if(pattern_copy[i]=='\0') break;
        } else if(char_idx<15) pattern_octets[octet_count][char_idx++] = pattern_copy[i];
    }
    if(octet_count!=4) return FALSE;
    for(int i=0; i<4; i++) {
        if(strcmp(pattern_octets[i], "*")==0) continue;
        if(atoi(pattern_octets[i]) != ip_octets[i]) return FALSE;
    }
    return TRUE;
}

BOOL match_port_pattern(const char *pattern, UINT16 port) {
    if (is_wildcard_str(pattern)) return TRUE;
    char *dash = strchr(pattern, '-');
    if (dash != NULL) {
        int start = atoi(pattern); int end = atoi(dash + 1);
        return (port >= start && port <= end);
    }
    return (port == atoi(pattern));
}

BOOL match_ip_list(const char *ip_list, UINT32 ip) {
    if (!ip_list || !ip_list[0] || is_wildcard_str(ip_list)) return TRUE;
    size_t len = strlen(ip_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, ip_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ";");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_ip_pattern(token, ip)) { matched = TRUE; break; }
        token = strtok(NULL, ";");
    }
    free(copy); return matched;
}

BOOL match_port_list(const char *port_list, UINT16 port) {
    if (!port_list || !port_list[0] || is_wildcard_str(port_list)) return TRUE;
    size_t len = strlen(port_list)+1; char *copy = malloc(len); if(!copy) return FALSE;
    strncpy(copy, port_list, len); BOOL matched = FALSE;
    char *token = strtok(copy, ",;");
    while(token) {
        while(*token==' '||*token=='\t') token++;
        if(match_port_pattern(token, port)) { matched = TRUE; break; }
        token = strtok(NULL, ",;");
    }
    free(copy); return matched;
}

// [Modified] Use  improved matching logic (Wildcard & Full Path Fixes)
BOOL match_process_pattern(const char *pattern, const char *process_full_path)
{
    if (is_wildcard_str(pattern)) return TRUE;

    // Windows path processing: Extract filename
    const char *filename = strrchr(process_full_path, '\\');
    if (filename != NULL) filename++;
    else filename = process_full_path;

    size_t pattern_len = strlen(pattern);
    size_t name_len = strlen(filename);
    size_t full_path_len = strlen(process_full_path);

    // Determine if Pattern contains path separators (if yes, match full path; otherwise match filename only)
    BOOL is_full_path_pattern = (strchr(pattern, '\\') != NULL || strchr(pattern, '/') != NULL);
    const char *match_target = is_full_path_pattern ? process_full_path : filename;
    size_t target_len = is_full_path_pattern ? full_path_len : name_len;

    // 1. "fire*" suffix wildcard
    if (pattern_len > 0 && pattern[pattern_len - 1] == '*') {
        return _strnicmp(pattern, match_target, pattern_len - 1) == 0;
    }

    // 2. "*.exe" prefix wildcard
    if (pattern_len > 1 && pattern[0] == '*') {
        const char *pattern_suffix = pattern + 1;
        size_t suffix_len = pattern_len - 1;
        if (target_len >= suffix_len) {
            return _stricmp(match_target + target_len - suffix_len, pattern_suffix) == 0;
        }
        return FALSE;
    }

    // 3. "fire*.exe" middle wildcard
    const char *star = strchr(pattern, '*');
    if (star != NULL) {
        size_t prefix_len = star - pattern;
        const char *suffix = star + 1;
        size_t suffix_len = strlen(suffix);

        if (_strnicmp(pattern, match_target, prefix_len) != 0) return FALSE;
        if (target_len < prefix_len + suffix_len) return FALSE;
        return _stricmp(match_target + target_len - suffix_len, suffix) == 0;
    }

    // 4. Exact match (Case Insensitive)
    return _stricmp(pattern, match_target) == 0;
}

// [Modified] Use List matching logic (more robust handling of quotes and whitespace)
BOOL match_process_list(const char *process_list, const char *process_name)
{
    if (process_list == NULL || process_list[0] == '\0' || is_wildcard_str(process_list)) return TRUE;
    size_t len = strlen(process_list) + 1;
    char *list_copy = (char *)malloc(len);
    if (!list_copy) return FALSE;

    strncpy(list_copy, process_list, len);
    BOOL matched = FALSE;
    char *token = strtok(list_copy, ",;");
    while (token != NULL) {
        // Remove leading whitespace
        while (*token == ' ' || *token == '\t') token++;
        
        // Remove trailing whitespace ( fix)
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0'; end--;
        }

        // Remove quotes "C:\path\app.exe"
        if (*token == '"' && strlen(token) > 1) {
            token++;
            char *quote = strchr(token, '"');
            if (quote != NULL) *quote = '\0';
        }

        if (match_process_pattern(token, process_name)) {
            matched = TRUE; break;
        }
        token = strtok(NULL, ",;");
    }
    free(list_copy); return matched;
}

BOOL is_broadcast_or_multicast(UINT32 ip) {
    if (ip == 0xFFFFFFFF) return TRUE;
    BYTE first = (ip >> 0) & 0xFF;
    if (first == 127) return TRUE; // Localhost
    if (first == 169 && ((ip >> 8) & 0xFF) == 254) return TRUE; // APIPA
    if ((ip & 0xFF000000) == 0xFF000000) return TRUE; // Subnet Broadcast
    if (first >= 224 && first <= 239) return TRUE; // Multicast
    return FALSE;
}