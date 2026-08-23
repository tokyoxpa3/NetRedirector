// --- START OF FILE NR_Core.c ---
#include "NR_Core.h"

// Define Handles
HANDLE windivert_handle = INVALID_HANDLE_VALUE;
HANDLE packet_threads[NUM_PACKET_THREADS];
HANDLE proxy_thread = NULL;
HANDLE udp_relay_thread = NULL;
HANDLE cleanup_thread_handle = NULL;
SOCKET udp_relay_socket = INVALID_SOCKET;
SOCKET udp_relay_socket6 = INVALID_SOCKET;

// === Helpers ===

// Swap two network-order addresses (IPv4 uses the first 4 bytes, IPv6 all 16)
static void swap_addr_bytes(int family, UINT8 *a, UINT8 *b)
{
    UINT8 tmp[16];
    int n = (family == AF_INET) ? 4 : 16;
    memcpy(tmp, a, n);
    memcpy(a, b, n);
    memcpy(b, tmp, n);
}

// === Packet Processor (WinDivert) ===

// [Added] WinDivertSend with error logging. A failed injection silently drops
// the packet; for the NAT-rewritten flows (returning/relay branches) a dropped
// packet means the rewrite is lost, so at least leave a trace. Rate-limited to
// avoid log storms under packet floods.
static void send_packet_checked(const unsigned char *packet, UINT packet_len, WINDIVERT_ADDRESS *addr, const char *what)
{
    if (WinDivertSend(windivert_handle, packet, packet_len, NULL, addr)) return;
    static volatile LONG send_fail_count = 0;
    LONG n = InterlockedIncrement(&send_fail_count);
    if (n == 1 || n % 100 == 0) {
        log_message("WinDivertSend failed (%s), error=%lu (occurrence %ld)",
            what, GetLastError(), n);
    }
}

// [Added] Per-packet NAT/rule processing, extracted verbatim from the old
// packet_processor loop body (the `continue`s became `return`s). Runs on a
// flow worker thread - or inline on the receiver when its queue is full.
static void process_packet(unsigned char *packet, UINT packet_len, WINDIVERT_ADDRESS *addr)
{
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;
    UINT8 *src_addr;
    UINT8 *dst_addr;
    int family;

    WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL, NULL, NULL,
        &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

    if (ip_header != NULL) {
        family = AF_INET;
        src_addr = (UINT8*)&ip_header->SrcAddr;
        dst_addr = (UINT8*)&ip_header->DstAddr;
    } else if (ipv6_header != NULL) {
        family = AF_INET6;
        src_addr = (UINT8*)ipv6_header->SrcAddr;
        dst_addr = (UINT8*)ipv6_header->DstAddr;
    } else {
        return;
    }

    // --- 以下邏輯對 IPv4 / IPv6 皆適用 (位址統一為 16 bytes) ---

    // UDP Logic
    if (udp_header != NULL && tcp_header == NULL) {
        if (addr->Outbound) {
            // 1. Returning from Relay
            if (udp_header->SrcPort == htons(LOCAL_UDP_RELAY_PORT)) {
                UINT16 dst_port = ntohs(udp_header->DstPort);
                UINT16 orig_dest_port;
                if (get_udp_dest_port_for_app(dst_port, &orig_dest_port)) {
                    udp_header->SrcPort = htons(orig_dest_port);
                    // Swap IPs
                    swap_addr_bytes(family, src_addr, dst_addr);
                }
                addr->Outbound = FALSE; // Inject to App
            }
            // 2. Tracked Outbound (keyed by src_port + destination: the
            // socket may send to several destinations)
            else if (is_connection_tracked_udp(ntohs(udp_header->SrcPort), family, dst_addr)) {
                UINT16 src_port = ntohs(udp_header->SrcPort);
                UINT32 proxy_id = 0;
                get_connection_udp(src_port, family, dst_addr, NULL, &proxy_id);

                if (proxy_id > 0) {
                    udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                    // Swap IPs
                    swap_addr_bytes(family, src_addr, dst_addr);
                    addr->Outbound = FALSE; // Inject to Relay
                }
            }
            // 3. New Connection
            else {
                UINT16 src_port = ntohs(udp_header->SrcPort);
                UINT16 dest_port = ntohs(udp_header->DstPort);
                UINT32 selected_proxy_id = 0;
                RuleAction action = handle_new_connection_logic(family, src_addr, dst_addr, src_port, dest_port, TRUE, &selected_proxy_id);

                if (action == RULE_ACTION_DIRECT) {
                    add_connection(src_port, family, src_addr, dst_addr, dest_port, 0, RULE_ACTION_DIRECT, TRUE);
                } else if (action == RULE_ACTION_BLOCK) {
                    return; // Drop
                } else if (action == RULE_ACTION_PROXY) {
                    add_connection(src_port, family, src_addr, dst_addr, dest_port, selected_proxy_id, RULE_ACTION_PROXY, TRUE);
                    udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                    swap_addr_bytes(family, src_addr, dst_addr);
                    addr->Outbound = FALSE;
                }
            }
        } else {
            if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT)) {
                send_packet_checked(packet, packet_len, addr, "udp passthrough");
                return;
            }
        }
        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
        send_packet_checked(packet, packet_len, addr, "udp rewritten");
        return;
    }

        // TCP Logic
        if (tcp_header != NULL) {
            int n = (family == AF_INET) ? 4 : 16;
            if (addr->Outbound) {
                // 1. Returning from Local Proxy
                if (tcp_header->SrcPort == htons(g_local_relay_port)) {
                    // Before any rewrite: dst_addr is the app-endpoint address,
                    // which equals the entry's original-destination component
                    // (the NAT swap made the relay's peer look like the original
                    // destination). It is both the lookup key and, after FIN/RST,
                    // the removal key.
                    UINT8 app_endpoint[16];
                    memcpy(app_endpoint, dst_addr, n);
                    UINT16 dst_port = ntohs(tcp_header->DstPort);
                    UINT8 orig_dest_addr[16];
                    UINT16 orig_dest_port;
                    if (get_connection(dst_port, family, app_endpoint, NULL, orig_dest_addr, &orig_dest_port, NULL, NULL)) {
                        tcp_header->SrcPort = htons(orig_dest_port);
                        // DstAddr := old SrcAddr (local app IP), SrcAddr := original destination
                        memcpy(dst_addr, src_addr, n);
                        memcpy(src_addr, orig_dest_addr, n);
                        if (tcp_header->Fin || tcp_header->Rst) remove_connection(dst_port, family, app_endpoint);
                    }
                    addr->Outbound = FALSE;
                }
                // 2. Tracked Outbound
                else if (is_connection_tracked(ntohs(tcp_header->SrcPort), family, dst_addr)) {
                    UINT16 src_port = ntohs(tcp_header->SrcPort);
                    UINT32 proxy_id = 0;
                    get_connection(src_port, family, dst_addr, NULL, NULL, NULL, &proxy_id, NULL);

                    if (tcp_header->Fin || tcp_header->Rst) remove_connection(src_port, family, dst_addr);

                    if (proxy_id > 0) {
                        tcp_header->DstPort = htons(g_local_relay_port);
                        swap_addr_bytes(family, src_addr, dst_addr);
                        addr->Outbound = FALSE; // Inject to Proxy
                    }
                }
            // 3. New Connection
            else {
                UINT16 src_port = ntohs(tcp_header->SrcPort);
                UINT16 dest_port = ntohs(tcp_header->DstPort);
                UINT32 selected_proxy_id = 0;
                RuleAction action = handle_new_connection_logic(family, src_addr, dst_addr, src_port, dest_port, FALSE, &selected_proxy_id);

                if (action == RULE_ACTION_DIRECT) {
                    add_connection(src_port, family, src_addr, dst_addr, dest_port, 0, RULE_ACTION_DIRECT, FALSE);
                } else if (action == RULE_ACTION_BLOCK) {
                    return;
                } else if (action == RULE_ACTION_PROXY) {
                    add_connection(src_port, family, src_addr, dst_addr, dest_port, selected_proxy_id, RULE_ACTION_PROXY, FALSE);
                    tcp_header->DstPort = htons(g_local_relay_port);
                    swap_addr_bytes(family, src_addr, dst_addr);
                    addr->Outbound = FALSE;
                }
            }
        } else {
            if (tcp_header->DstPort != htons(g_local_relay_port)) {
                send_packet_checked(packet, packet_len, addr, "tcp passthrough");
                return;
            }
        }
        WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
        send_packet_checked(packet, packet_len, addr, "tcp rewritten");
    }
}

// === Flow Dispatch (receiver + workers) ===
//
// [Fixed] Previously NUM_PACKET_THREADS threads all blocked in WinDivertRecv
// on the same handle. WinDivert hands each packet to exactly ONE waiting
// Recv call, so consecutive packets of the same flow could be picked up by
// different threads and re-injected in the wrong order (TCP retransmits /
// fast-retrans, UDP jitter for games).
//
// Now a single receiver thread pops packets from WinDivert and dispatches
// them by a direction-insensitive flow hash: every packet of a flow runs on
// the same worker in FIFO order, while different flows still process in
// parallel (the expensive new-connection rule evaluation no longer head-of-
// line blocks unrelated flows). When a worker queue is full the receiver
// processes that packet inline - a rare degradation that trades a slight
// reordering risk under extreme overload for not dropping the packet.

#define FLOW_WORKERS (NUM_PACKET_THREADS - 1)   // thread[0] is the receiver
#define FLOW_QUEUE_SLOTS 512

C_ASSERT(NUM_PACKET_THREADS >= 2);   // FLOW_WORKERS must be >= 1

typedef struct {
    unsigned char *pkt;      // heap copy owned by the queue until processed
    UINT len;
    WINDIVERT_ADDRESS addr;
} FLOW_SLOT;

typedef struct {
    CRITICAL_SECTION lock;   // short push/pop critical sections
    HANDLE sem;              // tokens == queued items
    FLOW_SLOT slots[FLOW_QUEUE_SLOTS];
    int head, tail, count;
} FLOW_QUEUE;

static FLOW_QUEUE g_flow_queues[FLOW_WORKERS];
static BOOL g_flow_queues_ready = FALSE;

BOOL flow_queues_init(void)
{
    memset(g_flow_queues, 0, sizeof(g_flow_queues));
    for (int i = 0; i < FLOW_WORKERS; i++) {
        InitializeCriticalSection(&g_flow_queues[i].lock);
        g_flow_queues[i].sem = CreateSemaphore(NULL, 0, FLOW_QUEUE_SLOTS, NULL);
        if (g_flow_queues[i].sem == NULL) {
            for (int j = 0; j < i; j++) {
                CloseHandle(g_flow_queues[j].sem);
                DeleteCriticalSection(&g_flow_queues[j].lock);
            }
            return FALSE;
        }
    }
    g_flow_queues_ready = TRUE;
    return TRUE;
}

// Drain and release every queue. Only valid after the receiver and all
// workers have been joined (Stop / Start-failure paths).
void flow_queues_shutdown(void)
{
    if (!g_flow_queues_ready) return;
    g_flow_queues_ready = FALSE;
    for (int i = 0; i < FLOW_WORKERS; i++) {
        FLOW_QUEUE *q = &g_flow_queues[i];
        while (q->count > 0) {
            free(q->slots[q->head].pkt);
            q->head = (q->head + 1) % FLOW_QUEUE_SLOTS;
            q->count--;
        }
        CloseHandle(q->sem);
        DeleteCriticalSection(&q->lock);
    }
}

// Direction-insensitive 5-tuple FNV-1a hash: both directions of the same
// conversation land on the same worker, which also keeps a flow's conntrack
// entry un-contended.
static UINT flow_hash(int family, BOOL is_tcp, const UINT8 *src, UINT16 sport, const UINT8 *dst, UINT16 dport)
{
    const UINT8 *a, *b;
    UINT16 pa, pb;
    int n = (family == AF_INET) ? 4 : 16;
    int cmp = memcmp(src, dst, n);
    if (cmp < 0 || (cmp == 0 && sport <= dport)) { a = src; pa = sport; b = dst; pb = dport; }
    else { a = dst; pa = dport; b = src; pb = sport; }

    UINT32 h = 2166136261u;
    for (int i = 0; i < n; i++) h = (h ^ a[i]) * 16777619u;
    h = (h ^ (UINT32)(pa & 0xFF)) * 16777619u;
    h = (h ^ (UINT32)(pa >> 8)) * 16777619u;
    for (int i = 0; i < n; i++) h = (h ^ b[i]) * 16777619u;
    h = (h ^ (UINT32)(pb & 0xFF)) * 16777619u;
    h = (h ^ (UINT32)(pb >> 8)) * 16777619u;
    h = (h ^ (is_tcp ? 0xABu : 0xCDu)) * 16777619u;
    return (UINT)h;
}

static void dispatch_packet(unsigned char *packet, UINT packet_len, WINDIVERT_ADDRESS *addr,
                            int family, BOOL is_tcp, const UINT8 *src, UINT16 sport,
                            const UINT8 *dst, UINT16 dport)
{
    FLOW_QUEUE *q = &g_flow_queues[flow_hash(family, is_tcp, src, sport, dst, dport) % FLOW_WORKERS];

    unsigned char *copy = (unsigned char*)malloc(packet_len);
    if (copy != NULL) {
        memcpy(copy, packet, packet_len);
        EnterCriticalSection(&q->lock);
        if (q->count < FLOW_QUEUE_SLOTS) {
            FLOW_SLOT *slot = &q->slots[q->tail];
            slot->pkt = copy;
            slot->len = packet_len;
            slot->addr = *addr;
            q->tail = (q->tail + 1) % FLOW_QUEUE_SLOTS;
            q->count++;
            LeaveCriticalSection(&q->lock);
            ReleaseSemaphore(q->sem, 1, NULL);
            return;
        }
        LeaveCriticalSection(&q->lock);
        free(copy);   // queue full -> fall through to inline processing
    }
    process_packet(packet, packet_len, addr);
}

DWORD WINAPI packet_receiver(LPVOID arg)
{
    unsigned char packet[MAXBUF];
    UINT packet_len;
    WINDIVERT_ADDRESS addr;
    PWINDIVERT_IPHDR ip_header;
    PWINDIVERT_IPV6HDR ipv6_header;
    PWINDIVERT_TCPHDR tcp_header;
    PWINDIVERT_UDPHDR udp_header;

    while (running)
    {
        if (!WinDivertRecv(windivert_handle, packet, sizeof(packet), &packet_len, &addr)) {
            DWORD error = GetLastError();

            // [修正重點] 過濾 995 (ERROR_OPERATION_ABORTED) 和 6 (ERROR_INVALID_HANDLE)
            // 當呼叫 NetRedirector_Stop 時，WinDivertClose 會觸發這些錯誤，這是正常的退出訊號。
            if (error == ERROR_INVALID_HANDLE || error == 995) {
                break; // 安靜地退出迴圈
            }

            log_message("Failed to receive packet (%lu)", error);
            continue;
        }

        WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL, NULL, NULL,
            &tcp_header, &udp_header, NULL, NULL, NULL, NULL);

        if (tcp_header == NULL && udp_header == NULL) continue;   // not TCP/UDP (filter guarantees this anyway)

        if (ip_header != NULL) {
            dispatch_packet(packet, packet_len, &addr, AF_INET, tcp_header != NULL,
                (const UINT8*)&ip_header->SrcAddr, ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort),
                (const UINT8*)&ip_header->DstAddr, ntohs(tcp_header ? tcp_header->DstPort : udp_header->DstPort));
        } else if (ipv6_header != NULL) {
            dispatch_packet(packet, packet_len, &addr, AF_INET6, tcp_header != NULL,
                (const UINT8*)ipv6_header->SrcAddr, ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort),
                (const UINT8*)ipv6_header->DstAddr, ntohs(tcp_header ? tcp_header->DstPort : udp_header->DstPort));
        }
    }
    return 0;
}

DWORD WINAPI flow_worker(LPVOID arg)
{
    int index = (int)(LONG_PTR)arg;
    FLOW_QUEUE *q = &g_flow_queues[index];

    while (running) {
        // 1 s timeout keeps `running` responsive during shutdown even if the
        // semaphore/count are momentarily out of sync after a timeout race.
        WaitForSingleObject(q->sem, 1000);

        unsigned char *pkt = NULL;
        UINT len = 0;
        WINDIVERT_ADDRESS addr;
        BOOL have = FALSE;

        EnterCriticalSection(&q->lock);
        if (q->count > 0) {
            FLOW_SLOT *slot = &q->slots[q->head];
            pkt = slot->pkt;
            len = slot->len;
            addr = slot->addr;
            q->head = (q->head + 1) % FLOW_QUEUE_SLOTS;
            q->count--;
            have = TRUE;
        }
        LeaveCriticalSection(&q->lock);

        if (have) {
            process_packet(pkt, len, &addr);
            free(pkt);
        }
    }
    return 0;
}

// === Transfer-Socket Registry ===
// (guarded by lock_connections; acquisitions are tiny push/remove walks and
// never nest with the conntrack operations)
//
// Stop() shuts every registered pair down with SD_BOTH, which unblocks the
// connection/transfer threads parked in recv() on those sockets. The owning
// threads then exit on their own and keep closesocket() ownership, so there
// is no double-close. Registration refuses new entries once stopping began
// (running == FALSE), preventing a fresh handler from outliving the shutdown.

typedef struct ACTIVE_SOCKET {
    SOCKET client_socket;
    SOCKET proxy_socket;
    struct ACTIVE_SOCKET *next;
} ACTIVE_SOCKET;

static ACTIVE_SOCKET *g_active_sockets = NULL;

BOOL register_connection_sockets(SOCKET client_socket, SOCKET proxy_socket)
{
    BOOL ok = FALSE;
    EnterCriticalSection(&lock_connections);
    if (running) {
        ACTIVE_SOCKET *entry = (ACTIVE_SOCKET*)malloc(sizeof(ACTIVE_SOCKET));
        if (entry != NULL) {
            entry->client_socket = client_socket;
            entry->proxy_socket = proxy_socket;
            entry->next = g_active_sockets;
            g_active_sockets = entry;
            ok = TRUE;
        }
    }
    LeaveCriticalSection(&lock_connections);
    return ok;
}

void unregister_connection_sockets(SOCKET client_socket, SOCKET proxy_socket)
{
    EnterCriticalSection(&lock_connections);
    ACTIVE_SOCKET **ptr = &g_active_sockets;
    while (*ptr != NULL) {
        if ((*ptr)->client_socket == client_socket && (*ptr)->proxy_socket == proxy_socket) {
            ACTIVE_SOCKET *entry = *ptr;
            *ptr = entry->next;
            free(entry);
            break;
        }
        ptr = &(*ptr)->next;
    }
    LeaveCriticalSection(&lock_connections);
}

void shutdown_all_connections(void)
{
    EnterCriticalSection(&lock_connections);
    while (g_active_sockets != NULL) {
        ACTIVE_SOCKET *entry = g_active_sockets;
        g_active_sockets = entry->next;
        if (entry->client_socket != INVALID_SOCKET) shutdown(entry->client_socket, SD_BOTH);
        if (entry->proxy_socket != INVALID_SOCKET) shutdown(entry->proxy_socket, SD_BOTH);
        free(entry);
    }
    LeaveCriticalSection(&lock_connections);
}

// === Cleanup Thread ===

DWORD WINAPI cleanup_thread(LPVOID arg)
{
    while (running) {
        // [Fixed] Was Sleep(10000): a sleeping cleanup thread could wake up
        // seconds AFTER NetRedirector_Stop finished and call EnterCriticalSection
        // on an already-deleted lock (Stop closes the handles, DllMain then
        // calls DeleteCriticalSection). Waiting on the stop event with a 10 s
        // timeout keeps the periodic sweep but lets Stop wake us immediately.
        if (g_stop_event != NULL) {
            if (WaitForSingleObject(g_stop_event, 10000) == WAIT_OBJECT_0) break;
        } else {
            Sleep(10000);   // fallback when the event could not be created
        }
        if (!running) break;
        DWORD current_time = GetTickCount();
        EnterCriticalSection(&lock_connections);
        CONNECTION_INFO **conn_ptr = &connection_list;
        while (*conn_ptr != NULL) {
            CONNECTION_INFO *curr = *conn_ptr;
            BOOL remove = FALSE;
            DWORD elapsed = current_time - curr->last_activity;
            DWORD timeout = curr->is_udp ? UDP_TIMEOUT_MS : TCP_TIMEOUT_MS;
            if (elapsed > timeout) remove = TRUE;

            if (remove) {
                *conn_ptr = curr->next;
                free(curr);
            } else {
                conn_ptr = &(*conn_ptr)->next;
            }
        }
        LeaveCriticalSection(&lock_connections);

        // Prune expired logged-connection dedup entries (10 minute TTL)
        prune_logged_connections(current_time, 600000);

        // [Added] Refresh the LAN/on-link cache each sweep: VPN/virtual
        // adapters may come up or renew their IP while running, and the cache
        // used to be built once at Start only. GetAdaptersAddresses at this
        // cadence is cheap. Readers tolerate the swap (worst case one sweep
        // uses the previous prefix set).
        refresh_local_addresses();
    }
    return 0;
}

// === Local TCP Proxy Server ===

DWORD WINAPI local_proxy_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    SOCKET listen_sock = INVALID_SOCKET;
    SOCKET listen_sock6 = INVALID_SOCKET;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return 1;

    // IPv4 listener
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock != INVALID_SOCKET) {
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(g_local_relay_port);

        if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR ||
            listen(listen_sock, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listen_sock);
            listen_sock = INVALID_SOCKET;
        }
    }

    // IPv6 listener (V6ONLY to avoid conflict with the IPv4 listener)
    listen_sock6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (listen_sock6 != INVALID_SOCKET) {
        setsockopt(listen_sock6, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(on));
        setsockopt(listen_sock6, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(g_local_relay_port);

        if (bind(listen_sock6, (struct sockaddr *)&addr6, sizeof(addr6)) == SOCKET_ERROR ||
            listen(listen_sock6, SOMAXCONN) == SOCKET_ERROR) {
            closesocket(listen_sock6);
            listen_sock6 = INVALID_SOCKET;
        }
    }

    if (listen_sock == INVALID_SOCKET && listen_sock6 == INVALID_SOCKET) { WSACleanup(); return 1; }

    log_message("Local proxy listening on port %d (IPv4%s/IPv6%s)",
        g_local_relay_port,
        listen_sock == INVALID_SOCKET ? " failed" : " ok",
        listen_sock6 == INVALID_SOCKET ? " failed" : " ok");

    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        if (listen_sock != INVALID_SOCKET) FD_SET(listen_sock, &read_fds);
        if (listen_sock6 != INVALID_SOCKET) FD_SET(listen_sock6, &read_fds);
        struct timeval timeout = {1, 0};
        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0) continue;

        // IPv4 accept
        if (listen_sock != INVALID_SOCKET && FD_ISSET(listen_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            int addr_len = sizeof(client_addr);
            SOCKET client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &addr_len);
            if (client_sock != INVALID_SOCKET) {
                CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
                if (!conn_config) { closesocket(client_sock); }
                else {
                    conn_config->client_socket = client_sock;
                    conn_config->family = AF_INET;
                    conn_config->orig_dest_port = ntohs(client_addr.sin_port);
                    conn_config->proxy_id = 0;
                    memset(conn_config->peer_addr, 0, sizeof(conn_config->peer_addr));
                    memcpy(conn_config->peer_addr, &client_addr.sin_addr, 4);

                    HANDLE t = CreateThread(NULL, 0, connection_handler, (LPVOID)conn_config, 0, NULL);
                    if (t) CloseHandle(t);
                    else { closesocket(client_sock); free(conn_config); }
                }
            }
        }

        // IPv6 accept
        if (listen_sock6 != INVALID_SOCKET && FD_ISSET(listen_sock6, &read_fds)) {
            struct sockaddr_in6 client_addr6;
            int addr_len = sizeof(client_addr6);
            SOCKET client_sock = accept(listen_sock6, (struct sockaddr *)&client_addr6, &addr_len);
            if (client_sock != INVALID_SOCKET) {
                CONNECTION_CONFIG *conn_config = (CONNECTION_CONFIG *)malloc(sizeof(CONNECTION_CONFIG));
                if (!conn_config) { closesocket(client_sock); }
                else {
                    conn_config->client_socket = client_sock;
                    conn_config->family = AF_INET6;
                    conn_config->orig_dest_port = ntohs(client_addr6.sin6_port);
                    conn_config->proxy_id = 0;
                    memcpy(conn_config->peer_addr, client_addr6.sin6_addr.s6_addr, 16);

                    HANDLE t = CreateThread(NULL, 0, connection_handler, (LPVOID)conn_config, 0, NULL);
                    if (t) CloseHandle(t);
                    else { closesocket(client_sock); free(conn_config); }
                }
            }
        }
    }
    if (listen_sock != INVALID_SOCKET) closesocket(listen_sock);
    if (listen_sock6 != INVALID_SOCKET) closesocket(listen_sock6);
    WSACleanup();
    return 0;
}

DWORD WINAPI connection_handler(LPVOID arg)
{
    CONNECTION_CONFIG *config = (CONNECTION_CONFIG *)arg;
    SOCKET client_sock = config->client_socket;

    // Lookup original destination
    // Key: (app source port + family + original destination address). The
    // accepted socket's peer endpoint IS the original destination - the NAT
    // swap rewrote the outbound SYN's source to it before injection.
    UINT8 dest_addr[16];
    int family;
    UINT16 dest_port;
    UINT32 proxy_id = 0;
    {
        int retries = 5;
        BOOL found = FALSE;
        while (retries-- > 0) {
            if (get_connection(config->orig_dest_port, config->family, config->peer_addr,
                &family, dest_addr, &dest_port, &proxy_id, NULL)) {
                found = TRUE; break;
            }
            Sleep(10);
        }
        if (!found) {
            closesocket(client_sock); free(config); return 0;
        }
    }

    PROXY_CONFIG selected_proxy_config;
    SOCKET proxy_sock;
    struct sockaddr_in proxy_addr;
    BOOL has_proxy = FALSE;

    EnterCriticalSection(&lock_proxies);
    if (proxy_id != 0) {
        PROXY_CONFIG *ptr = get_proxy_by_id(proxy_id);
        if (ptr && ptr->enabled) {
            selected_proxy_config = *ptr;
            has_proxy = TRUE;
        }
    } else {
        if (g_proxy_ip[0] != '\0' && g_proxy_port != 0) {
            memset(&selected_proxy_config, 0, sizeof(selected_proxy_config));
            strncpy(selected_proxy_config.proxy_ip, g_proxy_ip, sizeof(selected_proxy_config.proxy_ip)-1);
            selected_proxy_config.proxy_ip[sizeof(selected_proxy_config.proxy_ip)-1] = '\0';
            selected_proxy_config.proxy_port = g_proxy_port;
            selected_proxy_config.proxy_type = g_proxy_type;
            strncpy(selected_proxy_config.username, g_proxy_username, sizeof(selected_proxy_config.username)-1);
            selected_proxy_config.username[sizeof(selected_proxy_config.username)-1] = '\0';
            strncpy(selected_proxy_config.password, g_proxy_password, sizeof(selected_proxy_config.password)-1);
            selected_proxy_config.password[sizeof(selected_proxy_config.password)-1] = '\0';
            has_proxy = TRUE;
        }
    }
    LeaveCriticalSection(&lock_proxies);
    free(config);

    if (!has_proxy) { closesocket(client_sock); return 0; }

    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock == INVALID_SOCKET) { closesocket(client_sock); return 0; }

    // Socket Opts
    // [Fixed] Handshake phase gets a bounded timeout on the proxy socket: a
    // dead proxy used to park this thread forever in recv() during the
    // SOCKS5/HTTP handshake (the old code set SO_RCVTIMEO = 0 = infinite).
    // After the handshake succeeds the timeout is reset to infinite so the
    // established tunnel tolerates legitimately idle periods.
    #define PROXY_HANDSHAKE_TIMEOUT_MS 10000
    DWORD timeout = PROXY_HANDSHAKE_TIMEOUT_MS;
    int opt_val = 1;
    int buf_size = 64 * 1024;
    DWORD no_timeout = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&no_timeout, sizeof(no_timeout));
    setsockopt(proxy_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(proxy_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt_val, sizeof(opt_val));
    setsockopt(proxy_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt_val, sizeof(opt_val));
    setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));
    setsockopt(proxy_sock, SOL_SOCKET, SO_RCVBUF, (char*)&buf_size, sizeof(buf_size));

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = resolve_hostname(selected_proxy_config.proxy_ip);
    proxy_addr.sin_port = htons(selected_proxy_config.proxy_port);

    // 如果解析失敗 (0)，直接返回
    if (proxy_addr.sin_addr.s_addr == 0) {
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    // [Fixed] Bounded connect: blocking connect() burns ~21 s of SYN retries
    // on unreachable proxies while the client waits.
    if (!connect_with_timeout(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr), PROXY_HANDSHAKE_TIMEOUT_MS)) {
        closesocket(client_sock); closesocket(proxy_sock); return 0;
    }
    EnableKeepAlive(proxy_sock);

    int result = 0;
    if (selected_proxy_config.proxy_type == PROXY_TYPE_SOCKS5)
        result = socks5_connect_with_config(proxy_sock, family, dest_addr, dest_port, &selected_proxy_config);
    else
        result = http_connect_with_config(proxy_sock, family, dest_addr, dest_port, &selected_proxy_config);

    if (result != 0) {
        closesocket(client_sock); closesocket(proxy_sock); return 0;
    }

    // Tunnel is up: idle-tolerant from here on (browsers keep connections
    // open for minutes without traffic).
    setsockopt(proxy_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&no_timeout, sizeof(no_timeout));
    setsockopt(proxy_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&no_timeout, sizeof(no_timeout));

    TRANSFER_CONFIG *c1 = malloc(sizeof(TRANSFER_CONFIG));
    TRANSFER_CONFIG *c2 = malloc(sizeof(TRANSFER_CONFIG));
    if (!c1 || !c2) { closesocket(client_sock); closesocket(proxy_sock); if(c1)free(c1); if(c2)free(c2); return 0; }

    c1->from_socket = client_sock; c1->to_socket = proxy_sock;
    c2->from_socket = proxy_sock; c2->to_socket = client_sock;

    // [Added] Register the pair so Stop() can shutdown() these sockets and
    // unblock both transfer directions. Registration is refused once Stop has
    // begun - bail out instead of leaking a thread that outlives the shutdown.
    if (!register_connection_sockets(client_sock, proxy_sock)) {
        closesocket(client_sock); closesocket(proxy_sock); free(c1); free(c2); return 0;
    }

    // [Fixed] dwStackSize=1 was a mistake (rounded up to page granularity);
    // 0 = use the system default stack size.
    HANDLE t1 = CreateThread(NULL, 0, transfer_handler, c1, 0, NULL);
    if (!t1) {
        unregister_connection_sockets(client_sock, proxy_sock);
        closesocket(client_sock); closesocket(proxy_sock); free(c1); free(c2); return 0;
    }

    transfer_handler(c2); // Run one direction on this thread
    WaitForSingleObject(t1, INFINITE);
    CloseHandle(t1);

    // Unregister BEFORE closing: once Stop's shutdown-all walk releases the
    // lock, this pair is already gone and cannot be shutdown() by mistake
    // after the handle values get recycled.
    unregister_connection_sockets(client_sock, proxy_sock);
    closesocket(client_sock);
    closesocket(proxy_sock);
    return 0;
}

DWORD WINAPI transfer_handler(LPVOID arg)
{
    TRANSFER_CONFIG *config = (TRANSFER_CONFIG *)arg;
    SOCKET from = config->from_socket;
    SOCKET to = config->to_socket;
    char *buf = (char*)malloc(TRANSFER_BUF_SIZE);
    free(config);
    if (!buf) return 0;

    while (TRUE) {
        int len = recv(from, buf, TRANSFER_BUF_SIZE, 0);
        if (len <= 0) {
            shutdown(from, SD_RECEIVE);
            shutdown(to, SD_SEND);
            break;
        }
        int sent = 0;
        while (sent < len) {
            int n = send(to, buf + sent, len - sent, 0);
            if (n == SOCKET_ERROR) {
                shutdown(from, SD_BOTH); shutdown(to, SD_BOTH);
                free(buf); return 0;
            }
            sent += n;
        }
    }
    free(buf);
    return 0;
}

// === UDP Relay Server ===

DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr, from_addr;
    struct sockaddr_in6 local_addr6, from_addr6;
    unsigned char recv_buf[MAXBUF], send_buf[MAXBUF];
    int recv_len, from_len;
    int on = 1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return 1;

    // IPv4 relay socket (apps over IPv4)
    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket == INVALID_SOCKET) { WSACleanup(); return 1; }

    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(LOCAL_UDP_RELAY_PORT);

    if (bind(udp_relay_socket, (struct sockaddr *)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        closesocket(udp_relay_socket); udp_relay_socket = INVALID_SOCKET; WSACleanup(); return 1;
    }

    // IPv6 relay socket (apps over IPv6), V6ONLY to avoid conflict with IPv4 socket
    udp_relay_socket6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket6 != INVALID_SOCKET) {
        setsockopt(udp_relay_socket6, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(on));
        setsockopt(udp_relay_socket6, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));

        memset(&local_addr6, 0, sizeof(local_addr6));
        local_addr6.sin6_family = AF_INET6;
        local_addr6.sin6_addr = in6addr_any;
        local_addr6.sin6_port = htons(LOCAL_UDP_RELAY_PORT);

        if (bind(udp_relay_socket6, (struct sockaddr *)&local_addr6, sizeof(local_addr6)) == SOCKET_ERROR) {
            closesocket(udp_relay_socket6);
            udp_relay_socket6 = INVALID_SOCKET;
        }
    }

    log_message("UDP relay listening on port %d (IPv4%s/IPv6%s)", LOCAL_UDP_RELAY_PORT,
        udp_relay_socket == INVALID_SOCKET ? " failed" : " ok",
        udp_relay_socket6 == INVALID_SOCKET ? " failed" : " ok");

    while (running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        if (udp_relay_socket != INVALID_SOCKET) FD_SET(udp_relay_socket, &read_fds);
        if (udp_relay_socket6 != INVALID_SOCKET) FD_SET(udp_relay_socket6, &read_fds);
        SOCKET max_fd = udp_relay_socket;

        EnterCriticalSection(&lock_udp);
        UDP_ASSOCIATION *assoc = udp_associations;
        while (assoc != NULL) {
            FD_SET(assoc->control_socket, &read_fds);
            FD_SET(assoc->udp_socket, &read_fds);
            if (assoc->control_socket > max_fd) max_fd = assoc->control_socket;
            if (assoc->udp_socket > max_fd) max_fd = assoc->udp_socket;
            assoc = assoc->next;
        }
        LeaveCriticalSection(&lock_udp);

        struct timeval timeout = {1, 0};
        if (select(0, &read_fds, NULL, NULL, &timeout) <= 0) continue;

        // Local Apps (IPv4) -> Relay
        if (udp_relay_socket != INVALID_SOCKET && FD_ISSET(udp_relay_socket, &read_fds)) {
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
            if (recv_len > 0) {
                UINT16 from_port = ntohs(from_addr.sin_port);
                UINT8 dest_addr[16];
                UINT16 dest_port;
                UINT32 proxy_id;
                // Full-key lookup (app port + true destination IP from the
                // swapped source address): a socket sending to multiple
                // destinations must recover the per-destination port/proxy.
                if (get_connection_udp(from_port, AF_INET, (const UINT8*)&from_addr.sin_addr, &dest_port, &proxy_id)) {
                    // dest_addr = the true destination (equals the swapped source)
                    memset(dest_addr, 0, 16);
                    memcpy(dest_addr, &from_addr.sin_addr, 4);
                    UDP_ASSOCIATION *target_assoc = NULL;
                    EnterCriticalSection(&lock_udp);
                    assoc = udp_associations;
                    while (assoc != NULL) {
                        if (assoc->proxy_id == proxy_id) { target_assoc = assoc; break; }
                        assoc = assoc->next;
                    }
                    LeaveCriticalSection(&lock_udp);

                    if (!target_assoc) {
                        PROXY_CONFIG cfg_copy;
                        BOOL have_cfg = FALSE;
                        EnterCriticalSection(&lock_proxies);
                        PROXY_CONFIG *cfg = get_proxy_by_id(proxy_id);
                        if (cfg && cfg->enabled) { cfg_copy = *cfg; have_cfg = TRUE; }
                        LeaveCriticalSection(&lock_proxies);

                        if (have_cfg) {
                            target_assoc = establish_udp_associate_with_config(&cfg_copy);
                            if (target_assoc) {
                                EnterCriticalSection(&lock_udp);
                                target_assoc->next = udp_associations;
                                udp_associations = target_assoc;
                                LeaveCriticalSection(&lock_udp);
                            } else {
                                log_message("UDP relay: UDP ASSOCIATE failed (proxy id %u, %s:%u)", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            }
                        } else {
                            log_message("UDP relay: no usable proxy config (proxy id %u)", proxy_id);
                        }
                    }

                    if (target_assoc) {
                        send_buf[0]=0; send_buf[1]=0; send_buf[2]=0; send_buf[3]=SOCKS5_ATYP_IPV4;
                        memcpy(&send_buf[4], dest_addr, 4);
                        *(UINT16*)&send_buf[8] = htons(dest_port);
                        memcpy(&send_buf[10], recv_buf, recv_len);
                        if (sendto(target_assoc->udp_socket, (char*)send_buf, 10 + recv_len, 0,
                            (struct sockaddr *)&target_assoc->relay_addr, sizeof(target_assoc->relay_addr)) == SOCKET_ERROR) {
                            log_message("UDP relay: sendto proxy failed, error=%ld", WSAGetLastError());
                        }
                        target_assoc->last_activity = GetTickCount();
                    }
                }
            }
        }

        // Local Apps (IPv6) -> Relay
        if (udp_relay_socket6 != INVALID_SOCKET && FD_ISSET(udp_relay_socket6, &read_fds)) {
            from_len = sizeof(from_addr6);
            recv_len = recvfrom(udp_relay_socket6, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr6, &from_len);
            if (recv_len > 0) {
                UINT16 from_port = ntohs(from_addr6.sin6_port);
                UINT8 dest_addr[16];
                UINT16 dest_port;
                UINT32 proxy_id;
                // Full-key lookup (app port + true destination IP), IPv6 flavor
                if (get_connection_udp(from_port, AF_INET6, (const UINT8*)&from_addr6.sin6_addr, &dest_port, &proxy_id)) {
                    memcpy(dest_addr, from_addr6.sin6_addr.s6_addr, 16);
                    UDP_ASSOCIATION *target_assoc = NULL;
                    EnterCriticalSection(&lock_udp);
                    assoc = udp_associations;
                    while (assoc != NULL) {
                        if (assoc->proxy_id == proxy_id) { target_assoc = assoc; break; }
                        assoc = assoc->next;
                    }
                    LeaveCriticalSection(&lock_udp);

                    if (!target_assoc) {
                        PROXY_CONFIG cfg_copy;
                        BOOL have_cfg = FALSE;
                        EnterCriticalSection(&lock_proxies);
                        PROXY_CONFIG *cfg = get_proxy_by_id(proxy_id);
                        if (cfg && cfg->enabled) { cfg_copy = *cfg; have_cfg = TRUE; }
                        LeaveCriticalSection(&lock_proxies);

                        if (have_cfg) {
                            target_assoc = establish_udp_associate_with_config(&cfg_copy);
                            if (target_assoc) {
                                EnterCriticalSection(&lock_udp);
                                target_assoc->next = udp_associations;
                                udp_associations = target_assoc;
                                LeaveCriticalSection(&lock_udp);
                            } else {
                                log_message("UDP relay: UDP ASSOCIATE failed (IPv6, proxy id %u, %s:%u)", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            }
                        } else {
                            log_message("UDP relay: no usable proxy config (IPv6, proxy id %u)", proxy_id);
                        }
                    }

                    if (target_assoc) {
                        send_buf[0]=0; send_buf[1]=0; send_buf[2]=0; send_buf[3]=SOCKS5_ATYP_IPV6;
                        memcpy(&send_buf[4], dest_addr, 16);
                        *(UINT16*)&send_buf[20] = htons(dest_port);
                        memcpy(&send_buf[22], recv_buf, recv_len);
                        if (sendto(target_assoc->udp_socket, (char*)send_buf, 22 + recv_len, 0,
                            (struct sockaddr *)&target_assoc->relay_addr, sizeof(target_assoc->relay_addr)) == SOCKET_ERROR) {
                            log_message("UDP relay: sendto proxy failed (IPv6), error=%ld", WSAGetLastError());
                        }
                        target_assoc->last_activity = GetTickCount();
                    }
                }
            }
        }

        // Proxy -> Relay -> Apps
        // (holds lock_udp for the walk; briefly takes lock_connections inside —
        //  the reverse order never occurs anywhere, so this nesting is safe)
        EnterCriticalSection(&lock_udp);
        UDP_ASSOCIATION **assoc_ptr = &udp_associations;
        while (*assoc_ptr != NULL) {
            UDP_ASSOCIATION *curr = *assoc_ptr;
            BOOL remove = FALSE;
            
            // Check Control Socket
            if (FD_ISSET(curr->control_socket, &read_fds)) {
                char t[1];
                if (recv(curr->control_socket, t, 1, MSG_PEEK) <= 0) remove = TRUE;
            }

            // Check UDP Data
            if (!remove && FD_ISSET(curr->udp_socket, &read_fds)) {
                from_len = sizeof(from_addr);
                recv_len = recvfrom(curr->udp_socket, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
                if (recv_len > 10 && recv_buf[2] == 0 && recv_buf[3] == SOCKS5_ATYP_IPV4) {
                    curr->last_activity = GetTickCount();
                    UINT32 src_ip = *(UINT32*)&recv_buf[4];
                    UINT16 src_port = ntohs(*(UINT16*)&recv_buf[8]);
                    BOOL matched = FALSE;

                    EnterCriticalSection(&lock_connections);
                    CONNECTION_INFO *conn = connection_list;
                    while (conn != NULL) {
                        if (conn->is_udp && conn->family == AF_INET &&
                            conn->orig_dest_port == src_port &&
                            memcmp(conn->orig_dest_addr, &src_ip, 4) == 0) {
                            struct sockaddr_in target_addr;
                            memset(&target_addr, 0, sizeof(target_addr));
                            target_addr.sin_family = AF_INET;
                            memcpy(&target_addr.sin_addr.s_addr, conn->src_addr, 4);
                            target_addr.sin_port = htons(conn->src_port);
                            sendto(udp_relay_socket, (char*)&recv_buf[10], recv_len - 10, 0,
                                (struct sockaddr *)&target_addr, sizeof(target_addr));
                            matched = TRUE;
                            break;
                        }
                        conn = conn->next;
                    }
                    LeaveCriticalSection(&lock_connections);
                    if (!matched) {
                        log_message("UDP relay: response no matching connection (%u.%u.%u.%u:%u)",
                            recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7], src_port);
                    }
                }
                // SOCKS5 UDP header for IPv6: 4 (RSV/FRAG/ATYP) + 16 (addr) + 2 (port) = 22
                else if (recv_len > 22 && recv_buf[2] == 0 && recv_buf[3] == SOCKS5_ATYP_IPV6) {
                    curr->last_activity = GetTickCount();
                    UINT16 src_port = ntohs(*(UINT16*)&recv_buf[20]);
                    BOOL matched = FALSE;

                    EnterCriticalSection(&lock_connections);
                    CONNECTION_INFO *conn = connection_list;
                    while (conn != NULL) {
                        if (conn->is_udp && conn->family == AF_INET6 &&
                            conn->orig_dest_port == src_port &&
                            memcmp(conn->orig_dest_addr, &recv_buf[4], 16) == 0) {
                            if (udp_relay_socket6 != INVALID_SOCKET) {
                                struct sockaddr_in6 target_addr6;
                                memset(&target_addr6, 0, sizeof(target_addr6));
                                target_addr6.sin6_family = AF_INET6;
                                memcpy(&target_addr6.sin6_addr, conn->src_addr, 16);
                                target_addr6.sin6_port = htons(conn->src_port);
                                sendto(udp_relay_socket6, (char*)&recv_buf[22], recv_len - 22, 0,
                                    (struct sockaddr *)&target_addr6, sizeof(target_addr6));
                            }
                            matched = TRUE;
                            break;
                        }
                        conn = conn->next;
                    }
                    LeaveCriticalSection(&lock_connections);
                    if (!matched) {
                        log_message("UDP relay: response no matching connection (IPv6, port %u)", src_port);
                    }
                }
            }

            if (remove) {
                closesocket(curr->control_socket);
                closesocket(curr->udp_socket);
                *assoc_ptr = curr->next;
                free(curr);
            } else {
                assoc_ptr = &(*assoc_ptr)->next;
            }
        }
        LeaveCriticalSection(&lock_udp);
    }
    
    // Final Cleanup of Assocs
    clear_udp_associations();
    if (udp_relay_socket != INVALID_SOCKET) { closesocket(udp_relay_socket); udp_relay_socket = INVALID_SOCKET; }
    if (udp_relay_socket6 != INVALID_SOCKET) { closesocket(udp_relay_socket6); udp_relay_socket6 = INVALID_SOCKET; }
    WSACleanup();
    return 0;
}