// --- START OF FILE NR_Common.h ---
#ifndef NR_COMMON_H
#define NR_COMMON_H

// Prevent windows.h from including the old winsock.h, resolving macro redefinition errors
#define WIN32_LEAN_AND_MEAN

// Enable modern API fields (e.g. IP_ADAPTER_ADDRESSES.OperationalStatus)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x06010000
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <mstcpip.h>  // Include tcp_keepalive definition
#include <iphlpapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

// Include original header to get Enum definitions (ProxyType, RuleAction, RuleProtocol)
#include "NetRedirector.h" 

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// === Constants ===
#define MAXBUF 0xFFFF
#define LOCAL_PROXY_PORT 33100
#define LOCAL_UDP_RELAY_PORT 33200
#define MAX_PROCESS_NAME 256
#define TRANSFER_BUF_SIZE 65536
#define NUM_PACKET_THREADS 4
#define RULE_ACTION_PENDING 3
#define TCP_TIMEOUT_MS 3600000   // 1 hour
#define UDP_TIMEOUT_MS 600000    // 10 minutes

// How long a TCP entry survives after its close has been observed (FIN/RST).
//
// The entry has to outlive the last packets of the connection - the app's final
// ACK, a retransmitted FIN, and, for a relayed flow, the relay's own FIN - or
// those packets arrive with nothing to match and get misrouted. It must not
// outlive them by much either: entries are reaped only by the sweep, and
// get_connection() is a linear walk on the per-packet hot path, so every
// closed flow kept around is paid for by every open one.
#define TCP_CLOSING_GRACE_MS 30000

// Receive/send buffer for the UDP relay sockets and every UDP association
// socket. These carry all proxied UDP flows at once, and the Windows default
// is small enough that a burst (game map load, QUIC ramp-up) overflows it and
// drops datagrams - which a game client sees as packet loss.
#define UDP_SOCK_BUF_BYTES (1024 * 1024)

// Bound on the UDP ASSOCIATE dial + handshake. The relay is single-threaded, so
// this timeout is how long a dead/unreachable SOCKS5 proxy can stall EVERY
// proxied UDP flow while the association is (re)established. It must still be
// generous enough for a slow or loaded proxy: a timeout here does not just fail
// one datagram, it costs that proxy its entire UDP path until a retry succeeds.
#define UDP_ASSOC_TIMEOUT_MS 8000

// Per-proxy UDP ASSOCIATE retry backoff (see udp_assoc_backoff_note in NR_Core.c).
// A failed attempt doubles the wait up to the max; a success resets it.
//
// The first (UDP_ASSOC_BACKOFF_MIN_FAILS - 1) failures do NOT open a window at
// all - the next datagram retries immediately - so one transient failure cannot
// black out a working flow. While a window IS open every datagram for that
// proxy is dropped, so the cap must stay small enough that a recovered proxy is
// re-tried promptly instead of being punished for a failure that has passed.
#define UDP_ASSOC_BACKOFF_INIT_MS 500
#define UDP_ASSOC_BACKOFF_MAX_MS 5000
#define UDP_ASSOC_BACKOFF_MIN_FAILS 2

// Consecutive failed sendto()s to the proxy relay before the association is torn
// down. Most sendto failures on a UDP socket are transient and
// per-destination (WSAENOBUFS under a burst, a momentary WSAENETUNREACH while
// the upstream link blips); treating those as "the relay is dead" converts one
// lost datagram into a full re-dial for EVERY UDP flow on this proxy. The
// association is still reaped promptly when the relay really is gone, because
// the TCP control socket reaches EOF and the relay walk drops it.
#define UDP_ASSOC_SEND_FAIL_MAX 100

// Association liveness: a SOCKS5 UDP relay port dies SILENTLY.
//
// The proxy's BND.ADDR:BND.PORT is only as long-lived as the NAT mapping
// behind it. A phone hotspot that changes cell towers (or a carrier whose UDP
// NAT entry expires) stops forwarding on that port while the TCP control
// connection stays ESTABLISHED on keepalive - so select() never reports EOF
// and sendto() never fails, because UDP is connectionless. The association
// then black-holes every datagram for hours: measured on the dev machine, one
// established at 17:04 was still being used at 09:11 the next morning with
// zero replies, which surfaced as "Discord RTC -> no route" (every STUN
// binding request and every media packet went into the hole).
//
// The only observable signal is silence: we keep sending and nothing comes
// back. Drop the association after this much silence and the next datagram
// re-dials it, exactly like the sendto-failure path above.
//
// The counters are per association, and the "never replied" case gets a much
// wider window: a genuinely one-way flow (syslog, a fire-and-forget heartbeat)
// would otherwise be re-dialed every 15 seconds for no benefit.
#define UDP_ASSOC_RX_SILENCE_MS 15000
#define UDP_ASSOC_RX_SILENCE_DATAGRAMS 20
#define UDP_ASSOC_RX_SILENCE_MS_ONEWAY 60000
#define UDP_ASSOC_RX_SILENCE_DATAGRAMS_ONEWAY 200

// Max text length of an IP address (IPv6: 45 chars + null)
#define MAX_IP_STR 48

// === Struct Definitions ===

// Proxy Config structure definition
typedef struct PROXY_CONFIG {
    UINT32 proxy_id;
    char name[256];           // Proxy name
    char proxy_ip[64];        // Proxy IP
    UINT16 proxy_port;        // Proxy port
    ProxyType proxy_type;     // Proxy type
    char username[256];       // Username
    char password[256];       // Password
    BOOL enabled;             // Is enabled
    // [Added] socks5h-style remote DNS: hand the original hostname (recovered
    // from the DNS-snoop IP->domain map) to the proxy instead of the bare IP.
    // Lets the proxy do geo-correct resolution / avoids a local DNS leak. Only
    // meaningful when the hostname is known; otherwise the IP is used.
    // Must stay BEFORE `next`: PROXY_CONFIG_API mirrors this prefix exactly.
    BOOL send_domain_to_proxy;
    struct PROXY_CONFIG *next;
    // Internal-only state (not mirrored in PROXY_CONFIG_API): UDP ASSOCIATE
    // retry backoff so a dead proxy is not re-dialed once per datagram.
    DWORD udp_assoc_next_retry;   // GetTickCount() before which no retry is allowed
    DWORD udp_assoc_backoff_ms;   // current backoff window (0 = healthy)
    DWORD udp_assoc_fail_streak;  // consecutive failed dials; gates the backoff
} PROXY_CONFIG;

// Process Rule Structure
typedef struct PROCESS_RULE {
    UINT32 rule_id;
    char process_name[MAX_PROCESS_NAME];
    DWORD target_pid;     // New field: if 0 ignore, if non-zero match PID
    char *target_hosts;   // Dynamic: IP filter
    char *target_ports;   // Dynamic: Port filter
    RuleProtocol protocol;
    RuleAction action;
    UINT32 proxy_id;
    BOOL enabled;
    struct PROCESS_RULE *next;
} PROCESS_RULE;

// Connection Tracking Structure
// Addresses are stored in network byte order: IPv4 uses the first 4 bytes,
// IPv6 uses all 16 bytes. family indicates which interpretation is valid.
typedef struct CONNECTION_INFO {
    UINT16 src_port;
    int family;               // AF_INET or AF_INET6
    UINT8 src_addr[16];
    UINT8 orig_dest_addr[16];
    UINT16 orig_dest_port;
    UINT32 proxy_id;
    RuleAction action;
    BOOL is_udp;              // TRUE: UDP timeout applies, FALSE: TCP timeout
    // [Added] Set when a FIN/RST has been seen for this flow. The entry is kept
    // - not freed - so the packets that follow a close still match it, and is
    // reaped TCP_CLOSING_GRACE_MS after the close instead of TCP_TIMEOUT_MS.
    // A SYN for the same key re-classifies and clears it (see NR_Core.c).
    BOOL closing;
    DWORD last_activity;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

// UDP Relay Association
typedef struct UDP_ASSOCIATION {
    UINT32 proxy_id;
    SOCKET control_socket;
    SOCKET udp_socket;
    struct sockaddr_in relay_addr;
    DWORD last_activity;
    DWORD send_fail_streak;   // consecutive failed sendto()s to the proxy relay
    // [Added] Reply-silence tracking (see UDP_ASSOC_RX_SILENCE_MS). last_rx is
    // the establish time until the first reply arrives, so a relay that never
    // worked is still eventually re-dialed - just on the wider one-way window.
    DWORD last_rx;            // GetTickCount() of the last valid reply
    UINT32 tx_since_rx;       // datagrams sent since that reply
    BOOL rx_seen;             // TRUE once at least one reply has been observed
    struct UDP_ASSOCIATION *next;
} UDP_ASSOCIATION;

// Connection Config for Threads
typedef struct {
    SOCKET client_socket;
    int family;               // AF_INET or AF_INET6 (of the local app connection)
    UINT8 peer_addr[16];      // accepted socket's peer address (= original destination)
    UINT16 orig_dest_port;
    UINT32 proxy_id;
} CONNECTION_CONFIG;

// Data Transfer Config
typedef struct {
    SOCKET from_socket;
    SOCKET to_socket;
} TRANSFER_CONFIG;

// Logged Connection for Deduplication
typedef struct LOGGED_CONNECTION {
    DWORD pid;
    int family;               // AF_INET or AF_INET6
    UINT8 dest_addr[16];
    UINT16 dest_port;
    RuleAction action;
    DWORD timestamp;          // GetTickCount() at insert time, for TTL pruning
    struct LOGGED_CONNECTION *next;
} LOGGED_CONNECTION;

// === Shared Global Variables (Extern) ===

// Signalled by NetRedirector_Stop() so sleeping worker threads (cleanup thread)
// wake immediately and observe running == FALSE instead of staying inside a
// long Sleep() that could outlive DeleteCriticalSection.
extern HANDLE g_stop_event;

// Per-structure locks (replaces the former single global lock_cs so that
// packet threads touching the connection list no longer contend with rule /
// proxy / UDP-association lock holders).
//
// Lock ordering rule: never hold two of these at once, EXCEPT the UDP relay
// main walk may briefly take lock_connections while holding lock_udp (the
// reverse order never occurs). Keep acquisitions short.
extern CRITICAL_SECTION lock_rules;       // protects rules_list
extern CRITICAL_SECTION lock_connections; // protects connection_list
extern CRITICAL_SECTION lock_logged;      // protects logged_connections
extern CRITICAL_SECTION lock_proxies;     // protects proxy_configs + g_proxy_* globals
extern CRITICAL_SECTION lock_udp;         // protects udp_associations
extern CRITICAL_SECTION lock_pid_cache;   // protects the PID caches in NR_Utils.c

extern BOOL running;
extern DWORD g_current_process_id;

// Global Configuration
extern char g_proxy_ip[64];
extern UINT16 g_proxy_port;
extern UINT16 g_local_relay_port;
extern ProxyType g_proxy_type;
extern char g_proxy_username[256];
extern char g_proxy_password[256];
extern PROXY_CONFIG *proxy_configs;
extern UINT32 g_next_proxy_id;
extern UINT32 g_next_rule_id;
extern BOOL g_dns_via_proxy;
extern RuleAction g_unknown_process_action;

// Callbacks
extern LogCallback g_log_callback;
extern ConnectionCallback g_connection_callback;

// Handles
extern HANDLE windivert_handle;
extern HANDLE packet_threads[NUM_PACKET_THREADS];
extern HANDLE proxy_thread;
extern HANDLE udp_relay_thread;
extern SOCKET udp_relay_socket;
extern SOCKET udp_relay_socket6;

// Shared Helper Function for Logging
//
// log_message() writes to the GUI callback (if one is registered) AND to a
// rotating log file next to the DLL, so a fault that has already passed still
// leaves evidence behind. See the comment block above its definition in
// NetRedirector.c.
void log_message(const char *msg, ...);

// Rate-limited variant for paths that can fire once per connection - process
// classification, proxy dial, handshake. Those are exactly the paths whose
// failure is invisible today, but logging them verbatim would let one
// misconfigured rule flood the engine log with thousands of identical lines and
// turn the log itself into a second outage.
//
// Each `slot` prints its first occurrence immediately, then at most one line
// per `interval_ms`. The collapsed ones are counted and reported inside the
// next line that does print, so the log still proves the path is being hit
// instead of silently swallowing it. Slots are a small fixed set; an
// out-of-range slot falls back to plain log_message().
void log_message_throttled(UINT32 slot, DWORD interval_ms, const char *msg, ...);

#define NR_THROTTLE_SLOTS           16
#define NR_THROTTLE_UNKNOWN_PID      0  // pid unresolved -> fallback action applied
#define NR_THROTTLE_PROXY_DOWNGRADE  1  // PROXY action silently became DIRECT
#define NR_THROTTLE_NO_PROXY         2  // relay conn dropped: no usable proxy
#define NR_THROTTLE_RESOLVE_FAIL     3  // proxy hostname did not resolve
#define NR_THROTTLE_CONNECT_FAIL     4  // TCP connect to the proxy failed
#define NR_THROTTLE_HANDSHAKE_FAIL   5  // SOCKS5 / HTTP handshake failed
#define NR_THROTTLE_UNTRACKED        6  // relay conn with no tracked origin
#define NR_THROTTLE_NAME_LOOKUP      7  // OpenProcess on the owning pid failed
// The same "could not be attributed" message means two very different things
// depending on the protocol. For TCP it is a real signal - the connection
// tracking state machine is being asked about a flow it never saw. For UDP it
// is routine: UDP has no TIME_WAIT and no handshake, so the socket is often
// closed before the lookup runs (Dnscache is the usual culprit) and the
// datagram is forwarded unchanged either way. One busy DNS client was
// therefore burying every genuine line in the log. UDP gets its own slot and a
// far longer window; the TCP window is deliberately left alone.
#define NR_THROTTLE_UNKNOWN_PID_UDP  8  // pid unresolved on UDP -> normal, harmless
#define NR_THROTTLE_UNKNOWN_PID_UDP_MS 60000

#endif // NR_COMMON_H