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

// [Pure, host-testable] Source endpoint a packet returning from the relay must
// carry so the app sees the real remote server as the sender.
//
// The relay delivers its reply to the app's own address, so the packet seen
// here has the local relay socket as its source. A connect()ed UDP socket
// (which is what game clients use) silently discards any reply whose source is
// not its peer, so when the tracked flow endpoint is known the source must
// become the remote server - address AND port, taken from the same connection
// entry. Leaving the source as the app itself is exactly the bug this guards
// against.
//
// Returns TRUE when the source was rewritten; FALSE when it must stay as-is
// (no tracked endpoint, e.g. the flow already timed out).
BOOL udp_reply_source(int family,
                      const UINT8 *pkt_src_addr, UINT16 pkt_src_port,
                      BOOL have_remote, const UINT8 *remote_addr, UINT16 remote_port,
                      UINT8 *out_src_addr, UINT16 *out_src_port)
{
    if (out_src_addr == NULL || out_src_port == NULL) return FALSE;
    int n = (family == AF_INET) ? 4 : 16;
    memset(out_src_addr, 0, 16);

    if (have_remote && remote_addr != NULL) {
        memcpy(out_src_addr, remote_addr, n);
        *out_src_port = remote_port;
        return TRUE;
    }
    if (pkt_src_addr != NULL) memcpy(out_src_addr, pkt_src_addr, n);
    *out_src_port = pkt_src_port;
    return FALSE;
}

// [Pure, host-testable] Has this association gone quiet for long enough that
// its SOCKS5 relay port must be presumed dead?
//
// Two windows, because "no reply yet" and "replies stopped" mean different
// things. An association that has answered before is a two-way flow: if it
// sends 20+ datagrams and hears nothing for 15 s, the mapping is gone. One
// that has NEVER answered may simply be one-way traffic, so it gets 200
// datagrams / 60 s before the (comparatively expensive) re-dial.
//
// DWORD subtraction wraps correctly across the 49.7-day GetTickCount() rollover,
// which is why the elapsed time is computed as an unsigned difference.
BOOL udp_assoc_is_silent(const UDP_ASSOCIATION *assoc, DWORD now)
{
    if (assoc == NULL) return FALSE;
    if (assoc->rx_seen) {
        return assoc->tx_since_rx >= UDP_ASSOC_RX_SILENCE_DATAGRAMS &&
               (DWORD)(now - assoc->last_rx) > UDP_ASSOC_RX_SILENCE_MS;
    }
    return assoc->tx_since_rx >= UDP_ASSOC_RX_SILENCE_DATAGRAMS_ONEWAY &&
           (DWORD)(now - assoc->last_rx) > UDP_ASSOC_RX_SILENCE_MS_ONEWAY;
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
    PVOID udp_payload;
    UINT udp_payload_len;
    UINT8 *src_addr;
    UINT8 *dst_addr;
    int family;

    WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, NULL, NULL, NULL,
        &tcp_header, &udp_header, &udp_payload, &udp_payload_len, NULL, NULL);

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

    // [Added] Snapshot of the direction flag before any rewrite. Every rewrite
    // below flips Outbound TRUE -> FALSE, so a change in this flag is an exact
    // indicator that the packet was modified - or, in the case-1 lookup miss,
    // that it is being re-injected inbound without a rewrite and therefore
    // still needs a full checksum (an outbound packet may carry an offloaded
    // one). Untouched packets keep their original, already-valid checksum.
    BOOL was_outbound = addr->Outbound;

    // UDP Logic
    if (udp_header != NULL && tcp_header == NULL) {
        if (addr->Outbound) {
            // 1. Returning from Relay
            if (udp_header->SrcPort == htons(LOCAL_UDP_RELAY_PORT)) {
                // The relay sent this to the app's own address (src = us, dst =
                // app); rewrite the source to the real remote server. See
                // udp_reply_source() for why the source ADDRESS (not just the
                // port) must be restored. DstAddr/DstPort already hold the app
                // endpoint, so only the source side changes.
                UINT8 srv_addr[16] = {0};
                UINT16 srv_port = 0;
                BOOL have_remote = get_udp_reply_endpoint(ntohs(udp_header->DstPort), family,
                                                          srv_addr, &srv_port);
                UINT8 new_src[16] = {0};
                UINT16 new_src_port = 0;
                udp_reply_source(family, src_addr, ntohs(udp_header->SrcPort),
                                 have_remote, srv_addr, srv_port,
                                 new_src, &new_src_port);
                memcpy(src_addr, new_src, (family == AF_INET) ? 4 : 16);
                udp_header->SrcPort = htons(new_src_port);
                addr->Outbound = FALSE; // Inject to App
            }
            // 2. Tracked Outbound (keyed by src_port + destination: the
            // socket may send to several destinations)
            //
            // [Perf] One walk, not two. get_connection_udp() uses the identical
            // predicate to is_connection_tracked_udp() (is_udp + src_port +
            // family + memcmp on orig_dest_addr) and already reports whether the
            // flow was found, so the old is_connection_tracked_udp() +
            // get_connection_udp() pair walked the same list and took the same
            // lock twice for EVERY outbound datagram. Measured in
            // tests/bench_conn_contention.c (mode 3 vs mode 4): 104.0 -> 82.2 ns
            // at 1 thread, 233.7 -> 175.3 ns at 3 threads.
            else {
                UINT16 src_port = ntohs(udp_header->SrcPort);
                UINT32 proxy_id = 0;
                if (get_connection_udp(src_port, family, dst_addr, NULL, &proxy_id)) {
                    if (proxy_id > 0) {
                        udp_header->DstPort = htons(LOCAL_UDP_RELAY_PORT);
                        // Swap IPs
                        swap_addr_bytes(family, src_addr, dst_addr);
                        addr->Outbound = FALSE; // Inject to Relay
                    }
                }
                // 3. New Connection
                else {
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
            }
        } else {
            // DNS snooping: observe inbound plaintext DNS responses (UDP
            // source port 53) to feed the IP->domain reverse map behind
            // wildcard-subdomain rules. Observation only — the packet is still
            // passed through unchanged below. The parser rejects non-response
            // or malformed payloads cheaply.
            if (udp_header->SrcPort == htons(53)) {
                dns_snoop_parse_response((const UINT8*)udp_payload, udp_payload_len);
            }
            if (udp_header->DstPort != htons(LOCAL_UDP_RELAY_PORT)) {
                send_packet_checked(packet, packet_len, addr, "udp passthrough");
                return;
            }
        }
        if (was_outbound != addr->Outbound) {
            // Rewritten above -> header bytes changed, checksums must be redone.
            WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
            send_packet_checked(packet, packet_len, addr, "udp rewritten");
        } else {
            // Captured but untouched (a DIRECT flow, or an inbound datagram
            // addressed to the relay port). Re-injecting it unchanged keeps its
            // original, already-valid checksum - recomputing it here was pure
            // waste on a large share of the captured UDP traffic.
            send_packet_checked(packet, packet_len, addr, "udp passthrough");
        }
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
                    // destination). It is both the lookup key and, after
                    // FIN/RST, the key the closing grace is recorded under.
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
                        // [Changed] Was remove_connection(). Freeing the entry
                        // here left the app's own ACK and FIN with nothing to
                        // match, so they were re-classified as a new connection -
                        // and the relay's FIN could no longer be rewritten back
                        // to the app. Keep it for the closing grace instead.
                        if (tcp_header->Fin || tcp_header->Rst) mark_connection_closing(dst_port, family, app_endpoint);
                    }
                    addr->Outbound = FALSE;
                }
                // 2. Tracked Outbound
                //
                // [Perf] One walk, not two - see the UDP branch above and
                // tests/bench_conn_contention.c. get_connection() applies the
                // identical predicate to is_connection_tracked() and already
                // returns proxy_id, so the pair used to walk the same list and
                // take the same lock twice for every outbound packet.
                else {
                    UINT16 src_port = ntohs(tcp_header->SrcPort);
                    UINT32 proxy_id = 0;
                    RuleAction action = RULE_ACTION_DIRECT;
                    // [Added] A SYN can only ever start a connection, so it is
                    // never answered from the table: an entry under the same key
                    // is a leftover whose close was never observed, or one still
                    // inside its closing grace, and letting it win would route
                    // the new flow through the old flow's proxy and port. A
                    // retransmitted SYN re-classifies too, which is harmless -
                    // add_connection() just refreshes the same key.
                    if (!tcp_header->Syn &&
                        get_connection(src_port, family, dst_addr, NULL, NULL, NULL, &proxy_id, &action)) {
                        // [Changed] Was remove_connection(): the packets that
                        // follow a close still need this entry.
                        if (tcp_header->Fin || tcp_header->Rst) mark_connection_closing(src_port, family, dst_addr);

                        // [Added] A flow already judged BLOCK stays blocked. The
                        // verdict is remembered in the table precisely because
                        // the SYN guard below forwards untracked non-SYN packets
                        // instead of re-classifying them.
                        if (action == RULE_ACTION_BLOCK) return;

                        if (proxy_id > 0) {
                            tcp_header->DstPort = htons(g_local_relay_port);
                            swap_addr_bytes(family, src_addr, dst_addr);
                            addr->Outbound = FALSE; // Inject to Proxy
                        }
                    }
                    // 3. New Connection
                    //
                    // [Added] Only a SYN starts one. Any other untracked outbound
                    // packet belongs to a flow this engine never saw the SYN of -
                    // it was started while the engine was stopped, or it has
                    // already closed - and classifying it can only misroute it.
                    // For an already-closed flow there is no process left to
                    // attribute it to (a closed TCB sits in TIME_WAIT with
                    // dwOwningPid == 0), which is exactly where the flood of
                    // "could not be attributed" lines came from. Such packets now
                    // fall through untouched and are re-injected below with their
                    // original, already-valid checksum.
                    else if (tcp_header->Syn && !tcp_header->Rst) {
                        UINT16 dest_port = ntohs(tcp_header->DstPort);
                        UINT32 selected_proxy_id = 0;
                        RuleAction decision = handle_new_connection_logic(family, src_addr, dst_addr, src_port, dest_port, FALSE, &selected_proxy_id);

                        if (decision == RULE_ACTION_DIRECT) {
                            add_connection(src_port, family, src_addr, dst_addr, dest_port, 0, RULE_ACTION_DIRECT, FALSE);
                        } else if (decision == RULE_ACTION_BLOCK) {
                            // [Added] Record the verdict so the rest of this flow
                            // is dropped too. Without the entry its later packets
                            // would be untracked, and the guard above forwards
                            // untracked non-SYN packets - so a flow established
                            // before the rule changed would survive BLOCK.
                            add_connection(src_port, family, src_addr, dst_addr, dest_port, 0, RULE_ACTION_BLOCK, FALSE);
                            return;
                        } else if (decision == RULE_ACTION_PROXY) {
                            add_connection(src_port, family, src_addr, dst_addr, dest_port, selected_proxy_id, RULE_ACTION_PROXY, FALSE);
                            tcp_header->DstPort = htons(g_local_relay_port);
                            swap_addr_bytes(family, src_addr, dst_addr);
                            addr->Outbound = FALSE;
                        }
                    }
                }
        } else {
            if (tcp_header->DstPort != htons(g_local_relay_port)) {
                send_packet_checked(packet, packet_len, addr, "tcp passthrough");
                return;
            }
        }
        if (was_outbound != addr->Outbound) {
            // Rewritten above -> header bytes changed, checksums must be redone.
            WinDivertHelperCalcChecksums(packet, packet_len, addr, 0);
            send_packet_checked(packet, packet_len, addr, "tcp rewritten");
        } else {
            // Captured but untouched: a DIRECT flow (case 2 with proxy_id == 0,
            // or case 3 DIRECT), an untracked packet that is not a SYN (the new
            // guard in case 3), or an inbound packet addressed to the relay
            // port. Its checksum is already valid, so leave it alone - this is
            // the hot path for every DIRECT connection, which previously paid a
            // full checksum recomputation per packet for nothing.
            send_packet_checked(packet, packet_len, addr, "tcp unchanged");
        }
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

// Slot payload capacity allocated up front. Covers a standard 1500-byte
// Ethernet MTU with headroom; a slot grows on demand if a larger packet ever
// arrives (jumbo frame, oversized UDP datagram), so this is a floor and not a
// ceiling.
#define FLOW_SLOT_INIT_CAP 2048

C_ASSERT(NUM_PACKET_THREADS >= 2);   // FLOW_WORKERS must be >= 1

typedef struct {
    unsigned char *buf;      // preallocated payload storage, reused per packet
    UINT cap;                // bytes allocated at buf (>= FLOW_SLOT_INIT_CAP)
    UINT len;                // valid payload length of the queued packet
    WINDIVERT_ADDRESS addr;
} FLOW_SLOT;

typedef struct {
    CRITICAL_SECTION lock;   // short push/pop critical sections
    HANDLE wake;             // auto-reset: "queue non-empty, drain it"
    // [Perf] Gates the wake signal so it fires on the idle->busy transition
    // instead of once per packet. SetEvent is a kernel transition (~309 ns
    // measured even with nobody waiting), and the worker drains the whole
    // backlog per wakeup, so all but the first signal of a burst are redundant.
    // See tests/bench_dispatch_wake.c: 444.8 -> 95.3 ns/pkt.
    volatile LONG wake_pending;
    FLOW_SLOT slots[FLOW_QUEUE_SLOTS];
    int head, tail, count;
} FLOW_QUEUE;

static FLOW_QUEUE g_flow_queues[FLOW_WORKERS];
static BOOL g_flow_queues_ready = FALSE;

static void flow_queue_release(FLOW_QUEUE *q)
{
    if (q->wake != NULL) { CloseHandle(q->wake); q->wake = NULL; }
    for (int s = 0; s < FLOW_QUEUE_SLOTS; s++) {
        free(q->slots[s].buf);
        q->slots[s].buf = NULL;
        q->slots[s].cap = 0;
    }
    q->head = q->tail = q->count = 0;
    q->wake_pending = 0;
}

BOOL flow_queues_init(void)
{
    memset(g_flow_queues, 0, sizeof(g_flow_queues));
    for (int i = 0; i < FLOW_WORKERS; i++) {
        FLOW_QUEUE *q = &g_flow_queues[i];
        InitializeCriticalSection(&q->lock);
        // [Changed] Auto-reset event instead of a counting semaphore. The
        // worker drains the entire backlog per wakeup, so a per-packet token
        // would leave the semaphore permanently over-counted (one release per
        // packet, one wait per burst) and spin the worker on stale tokens.
        q->wake = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (q->wake == NULL) {
            for (int j = 0; j <= i; j++) {
                flow_queue_release(&g_flow_queues[j]);
                DeleteCriticalSection(&g_flow_queues[j].lock);
            }
            memset(g_flow_queues, 0, sizeof(g_flow_queues));
            return FALSE;
        }
        // [Changed] Payload storage is allocated once per slot and reused,
        // instead of malloc()/free() per packet. The old code allocated a heap
        // block for every captured packet, so 1 receiver + 3 workers all
        // contended on the process heap for what is a fixed-size, very
        // short-lived object - the case the heap is worst at. A slot buffer is
        // never touched by two threads at once (see dispatch_packet /
        // flow_worker: a slot keeps counting towards q->count until its worker
        // has finished with it), so reuse needs no extra synchronisation.
        for (int s = 0; s < FLOW_QUEUE_SLOTS; s++) {
            q->slots[s].buf = (unsigned char*)malloc(FLOW_SLOT_INIT_CAP);
            if (q->slots[s].buf == NULL) {
                log_message("Failed to allocate flow queue %d slot %d (%d bytes); "
                    "packet dispatch unavailable", i, s, (int)FLOW_SLOT_INIT_CAP);
                for (int j = 0; j <= i; j++) {
                    flow_queue_release(&g_flow_queues[j]);
                    DeleteCriticalSection(&g_flow_queues[j].lock);
                }
                memset(g_flow_queues, 0, sizeof(g_flow_queues));
                return FALSE;
            }
            q->slots[s].cap = FLOW_SLOT_INIT_CAP;
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
        flow_queue_release(&g_flow_queues[i]);
        DeleteCriticalSection(&g_flow_queues[i].lock);
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
    BOOL queued = FALSE;

    EnterCriticalSection(&q->lock);
    if (q->count < FLOW_QUEUE_SLOTS) {
        FLOW_SLOT *slot = &q->slots[q->tail];
        // Steady state allocates nothing: the slot buffer is reused. It only
        // grows when a packet exceeds the slot's current capacity.
        if (slot->cap < packet_len) {
            unsigned char *grown = (unsigned char*)realloc(slot->buf, packet_len);
            if (grown != NULL) { slot->buf = grown; slot->cap = packet_len; }
        }
        if (slot->cap >= packet_len) {
            memcpy(slot->buf, packet, packet_len);
            slot->len = packet_len;
            slot->addr = *addr;
            q->tail = (q->tail + 1) % FLOW_QUEUE_SLOTS;
            q->count++;
            queued = TRUE;
        }
    }
    LeaveCriticalSection(&q->lock);

    if (queued) {
        // [Perf] Signal only on the idle->busy transition. SetEvent is a kernel
        // transition costing ~309 ns even with nobody waiting, while the worker
        // drains the ENTIRE backlog per wakeup - so signalling once per packet
        // was ~350 ns of pure waste per packet (79% of the dispatch cost).
        // flow_worker() resets the flag after it finds the queue empty, which
        // is what re-arms this. See tests/bench_dispatch_wake.c.
        if (InterlockedExchange(&q->wake_pending, 1) == 0) SetEvent(q->wake);
        return;
    }
    // Queue full, or the slot buffer could not be grown -> process inline. A
    // rare degradation that trades a slight reordering risk under extreme
    // overload for not dropping the packet.
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
        // [Perf] Re-arm the wake gate, then re-check the queue before sleeping.
        // The ORDER is load-bearing: resetting the flag AFTER an emptiness check
        // loses a wakeup - a producer that enqueues in that gap sees
        // wake_pending == 1, skips SetEvent, and its packet then sits until the
        // 1 s timeout. Resetting first means a packet enqueued after this point
        // either makes the re-check below see it, or signals the event.
        InterlockedExchange(&q->wake_pending, 0);

        BOOL idle;
        EnterCriticalSection(&q->lock);
        idle = (q->count == 0);
        LeaveCriticalSection(&q->lock);

        // 1 s timeout keeps `running` responsive during shutdown even if the
        // wake event and q->count are momentarily out of sync.
        if (idle) WaitForSingleObject(q->wake, 1000);

        // Drain the whole backlog per wakeup: one wait per burst instead of
        // one wait per packet.
        for (;;) {
            unsigned char *buf = NULL;
            UINT len = 0;
            WINDIVERT_ADDRESS addr;

            EnterCriticalSection(&q->lock);
            if (q->count > 0) {
                FLOW_SLOT *slot = &q->slots[q->head];
                buf = slot->buf;
                len = slot->len;
                addr = slot->addr;
            }
            LeaveCriticalSection(&q->lock);

            if (buf == NULL) break;

            process_packet(buf, len, &addr);

            // Release the slot only AFTER processing. While head is unadvanced
            // the slot still counts towards q->count, so the receiver can never
            // enqueue into a buffer that is still in use.
            EnterCriticalSection(&q->lock);
            q->head = (q->head + 1) % FLOW_QUEUE_SLOTS;
            q->count--;
            LeaveCriticalSection(&q->lock);
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
            // [Added] A flow whose close was observed is reaped on the short
            // grace instead of the idle timeout - see
            // mark_connection_closing(). Flows that never saw a FIN/RST keep the
            // idle timeout, exactly as before.
            DWORD timeout;
            if (curr->is_udp) timeout = UDP_TIMEOUT_MS;
            else if (curr->closing) timeout = TCP_CLOSING_GRACE_MS;
            else timeout = TCP_TIMEOUT_MS;
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
            // Silent before. A burst of these means the NAT rewrite and the
            // connection table have diverged - worth seeing, not worth a line
            // per occurrence.
            log_message_throttled(NR_THROTTLE_UNTRACKED, 2000,
                "Relay connection dropped: no tracked flow matched the relay peer "
                "(family %d, orig dest port %u) after 5 lookups",
                config->family, (unsigned)config->orig_dest_port);
            closesocket(client_sock); free(config); return 0;
        }
    }

    PROXY_CONFIG selected_proxy_config;
    SOCKET proxy_sock;
    struct sockaddr_in proxy_addr;
    BOOL has_proxy = FALSE;
    // [Added] Human-readable original destination, for the failure logs below.
    // Every one of these paths used to close the socket and return in total
    // silence, which is why "proxied traffic died after a restart" could never
    // be traced to a cause.
    char dest_str[MAX_IP_STR];

    addr_to_string(family, dest_addr, dest_str, sizeof(dest_str));

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

    if (!has_proxy) {
        // [Added] This was a total black hole: the client socket was closed and
        // nothing anywhere said why. It is also the most plausible way for
        // "everything is proxied" to quietly become "nothing is proxied" - the
        // rule still says PROXY, but the proxy it points at is gone or
        // disabled, so no relay can be built and the connection just dies.
        log_message_throttled(NR_THROTTLE_NO_PROXY, 2000,
            "Dropped connection to %s:%u: rule selected PROXY but no usable proxy "
            "config exists (proxy_id=%u, default proxy='%s:%u')",
            dest_str, (unsigned)dest_port, proxy_id,
            g_proxy_ip, (unsigned)g_proxy_port);
        closesocket(client_sock);
        return 0;
    }

    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock == INVALID_SOCKET) {
        log_message_throttled(NR_THROTTLE_CONNECT_FAIL, 5000,
            "Dropped connection to %s:%u: socket() for the proxy tunnel failed (%d)",
            dest_str, (unsigned)dest_port, WSAGetLastError());
        closesocket(client_sock);
        return 0;
    }

    // Socket Opts
    // [Fixed] Handshake phase gets a bounded timeout on the proxy socket: a
    // dead proxy used to park this thread forever in recv() during the
    // SOCKS5/HTTP handshake (the old code set SO_RCVTIMEO = 0 = infinite).
    // After the handshake succeeds the timeout is reset to infinite so the
    // established tunnel tolerates legitimately idle periods.
    #define PROXY_HANDSHAKE_TIMEOUT_MS 10000
    DWORD timeout = PROXY_HANDSHAKE_TIMEOUT_MS;
    int opt_val = 1;
    DWORD no_timeout = 0;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&no_timeout, sizeof(no_timeout));
    setsockopt(proxy_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(proxy_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(client_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt_val, sizeof(opt_val));
    setsockopt(proxy_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&opt_val, sizeof(opt_val));

    // [Removed] SO_RCVBUF used to be pinned to 64 KB on BOTH sockets here.
    // On Windows, *calling* setsockopt(SO_RCVBUF) disables receive-window
    // auto-tuning for that socket, so the advertised window stayed pinned near
    // 64 KB for the whole connection. The tunnel socket (proxy_sock) therefore
    // capped a single flow at roughly 64 KB / RTT.
    //
    // Measured on this machine (interleaved, 6 rounds each, same destination
    // and same file, only the setsockopt differing):
    //   setsockopt(SO_RCVBUF, 64KB)   min 171.6  avg 230.9  max 281.6 Mbps
    //   no setsockopt (auto-tune)     min 263.7  avg 281.0  max 296.2 Mbps
    //   setsockopt(SO_RCVBUF, 256KB)  min 261.5  avg 279.2  max 294.8 Mbps
    // End to end through the relay, the 64 KB pin cost 183-198 Mbps against a
    // path that sustains 244-300 Mbps (RTT ~2.5 ms awake; the BDP at 280 Mbps
    // is already ~88 KB, before the 80-120 ms Wi-Fi latency spikes).
    //
    // NOTE: Windows' DEFAULT SO_RCVBUF is already 65536 - the regression comes
    // from *calling* setsockopt, not from the value chosen. Do not re-add this
    // "to save memory": auto-tuning sizes the buffer to the BDP, and even a few
    // hundred concurrent tunnels only cost tens of MB.

    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = resolve_hostname(selected_proxy_config.proxy_ip);
    proxy_addr.sin_port = htons(selected_proxy_config.proxy_port);

    // 如果解析失敗 (0)，直接返回
    if (proxy_addr.sin_addr.s_addr == 0) {
        log_message_throttled(NR_THROTTLE_RESOLVE_FAIL, 5000,
            "Dropped connection to %s:%u: proxy hostname '%s' (id=%u) did not resolve",
            dest_str, (unsigned)dest_port, selected_proxy_config.proxy_ip,
            selected_proxy_config.proxy_id);
        closesocket(client_sock);
        closesocket(proxy_sock);
        return 0;
    }

    // [Fixed] Bounded connect: blocking connect() burns ~21 s of SYN retries
    // on unreachable proxies while the client waits.
    if (!connect_with_timeout(proxy_sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr), PROXY_HANDSHAKE_TIMEOUT_MS)) {
        // [Added] WSA error is the whole diagnosis here (WSAETIMEDOUT = the
        // proxy did not answer; WSAENETUNREACH = this machine has no route to
        // it), and it used to be discarded.
        log_message_throttled(NR_THROTTLE_CONNECT_FAIL, 5000,
            "Dropped connection to %s:%u: cannot reach proxy %s:%u (WSA error %d)",
            dest_str, (unsigned)dest_port, selected_proxy_config.proxy_ip,
            (unsigned)selected_proxy_config.proxy_port, WSAGetLastError());
        closesocket(client_sock); closesocket(proxy_sock); return 0;
    }
    EnableKeepAlive(proxy_sock);

    int result = 0;
    if (selected_proxy_config.proxy_type == PROXY_TYPE_SOCKS5)
        result = socks5_connect_with_config(proxy_sock, family, dest_addr, dest_port, &selected_proxy_config);
    else
        result = http_connect_with_config(proxy_sock, family, dest_addr, dest_port, &selected_proxy_config);

    if (result != 0) {
        log_message_throttled(NR_THROTTLE_HANDSHAKE_FAIL, 5000,
            "Dropped connection to %s:%u: %s handshake with proxy %s:%u failed (result=%d)",
            dest_str, (unsigned)dest_port,
            selected_proxy_config.proxy_type == PROXY_TYPE_SOCKS5 ? "SOCKS5" : "HTTP",
            selected_proxy_config.proxy_ip,
            (unsigned)selected_proxy_config.proxy_port, result);
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

// Upper bound on datagrams drained from one socket per select() round. Keeps
// the time an association can hold lock_udp during a burst bounded.
#define UDP_RELAY_DRAIN_MAX 64

// Non-blocking "is another datagram already queued on this socket?" probe.
// Lets a socket be drained completely inside a single select() round. The old
// code read exactly one datagram per readable socket per round, so a burst cost
// one select() syscall per datagram - and select() is O(fds), which gets
// expensive once several UDP associations are open.
static BOOL udp_socket_has_pending(SOCKET s)
{
    u_long avail = 0;
    if (s == INVALID_SOCKET) return FALSE;
    if (ioctlsocket(s, FIONREAD, &avail) != 0) return FALSE;
    return avail > 0;
}

// [Added] Per-proxy UDP ASSOCIATE retry backoff.
//
// The UDP relay runs on a single thread and establish_udp_associate_with_config()
// dials the proxy inline (bounded by UDP_ASSOC_TIMEOUT_MS). Without a backoff a
// dead proxy makes every datagram pay that full timeout and stalls every other
// association's traffic. These helpers space attempts for one proxy by an
// exponentially growing window (reset on success) so the caller can skip the
// datagram entirely while the window is open.
//
// The window lives on the shared PROXY_CONFIG (not the copy handed to
// establish), so it survives across datagrams. It only opens after
// UDP_ASSOC_BACKOFF_MIN_FAILS consecutive failures - see udp_assoc_backoff_note.
static BOOL udp_assoc_backoff_allow(UINT32 proxy_id, PROXY_CONFIG *out_cfg, BOOL *out_have_cfg)
{
    BOOL allow = FALSE;
    if (out_have_cfg) *out_have_cfg = FALSE;
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *cfg = get_proxy_by_id(proxy_id);
    if (cfg != NULL && cfg->enabled) {
        if (out_have_cfg) *out_have_cfg = TRUE;
        DWORD now = GetTickCount();
        // (LONG) cast keeps the comparison correct across GetTickCount() wrap.
        if (cfg->udp_assoc_next_retry == 0 ||
            (LONG)(now - cfg->udp_assoc_next_retry) >= 0) {
            if (out_cfg != NULL) *out_cfg = *cfg;
            allow = TRUE;
        }
    }
    LeaveCriticalSection(&lock_proxies);
    return allow;
}

// Record the outcome of one UDP ASSOCIATE attempt for a proxy. Returns TRUE if a
// retry-backoff window is now active (the caller drops this proxy's datagrams
// until it expires), FALSE if the next datagram may retry immediately.
//
// The first (UDP_ASSOC_BACKOFF_MIN_FAILS - 1) consecutive failures do not open a
// window at all: a single transient failure must not cost a working flow its UDP
// path. Only a SUSTAINED failure starts gating - that is the case the backoff
// exists for, where every datagram would otherwise pay a full
// UDP_ASSOC_TIMEOUT_MS while the relay thread is blocked in the dial.
static BOOL udp_assoc_backoff_note(UINT32 proxy_id, BOOL success)
{
    BOOL gated = FALSE;
    EnterCriticalSection(&lock_proxies);
    PROXY_CONFIG *cfg = get_proxy_by_id(proxy_id);
    if (cfg != NULL) {
        if (success) {
            cfg->udp_assoc_backoff_ms = 0;
            cfg->udp_assoc_next_retry = 0;
            cfg->udp_assoc_fail_streak = 0;
        } else {
            cfg->udp_assoc_fail_streak++;
            if (cfg->udp_assoc_fail_streak >= UDP_ASSOC_BACKOFF_MIN_FAILS) {
                DWORD b = cfg->udp_assoc_backoff_ms ? cfg->udp_assoc_backoff_ms * 2
                                                    : UDP_ASSOC_BACKOFF_INIT_MS;
                if (b > UDP_ASSOC_BACKOFF_MAX_MS) b = UDP_ASSOC_BACKOFF_MAX_MS;
                cfg->udp_assoc_backoff_ms = b;
                cfg->udp_assoc_next_retry = GetTickCount() + b;
                gated = TRUE;
            }
        }
    }
    LeaveCriticalSection(&lock_proxies);
    return gated;
}

// Close and drop the association for one proxy so the next datagram re-dials it.
// Called when a sendto to the proxy fails: the association's UDP relay is gone
// even if the TCP control socket has not been detected as closed yet, and the
// lazy establish path would otherwise never recover until that socket dies.
// Relay-thread only (no other thread touches the association sockets).
static void udp_assoc_drop(UINT32 proxy_id)
{
    EnterCriticalSection(&lock_udp);
    UDP_ASSOCIATION **pp = &udp_associations;
    while (*pp != NULL) {
        if ((*pp)->proxy_id == proxy_id) {
            UDP_ASSOCIATION *dead = *pp;
            *pp = dead->next;
            closesocket(dead->control_socket);
            closesocket(dead->udp_socket);
            free(dead);
            break;
        }
        pp = &(*pp)->next;
    }
    LeaveCriticalSection(&lock_udp);
}

DWORD WINAPI udp_relay_server(LPVOID arg)
{
    WSADATA wsa_data;
    struct sockaddr_in local_addr, from_addr;
    struct sockaddr_in6 local_addr6, from_addr6;
    unsigned char recv_buf[MAXBUF], send_buf[MAXBUF];
    int recv_len, from_len;
    int on = 1;
    int udp_buf = UDP_SOCK_BUF_BYTES;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return 1;

    // IPv4 relay socket (apps over IPv4)
    udp_relay_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_relay_socket == INVALID_SOCKET) { WSACleanup(); return 1; }

    setsockopt(udp_relay_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_RCVBUF, (const char*)&udp_buf, sizeof(udp_buf));
    setsockopt(udp_relay_socket, SOL_SOCKET, SO_SNDBUF, (const char*)&udp_buf, sizeof(udp_buf));
    disable_udp_connreset(udp_relay_socket);

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
        setsockopt(udp_relay_socket6, SOL_SOCKET, SO_RCVBUF, (const char*)&udp_buf, sizeof(udp_buf));
        setsockopt(udp_relay_socket6, SOL_SOCKET, SO_SNDBUF, (const char*)&udp_buf, sizeof(udp_buf));
        disable_udp_connreset(udp_relay_socket6);

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
          for (int _drain = 0; _drain < UDP_RELAY_DRAIN_MAX; _drain++) {
            if (_drain > 0 && !udp_socket_has_pending(udp_relay_socket)) break;
            from_len = sizeof(from_addr);
            recv_len = recvfrom(udp_relay_socket, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
            if (recv_len <= 0) break;
            {   // bare block: keeps the original body indentation after the change
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
                        // Skip entirely while this proxy is in its retry-backoff
                        // window - avoids re-dialing a dead proxy per datagram.
                        if (udp_assoc_backoff_allow(proxy_id, &cfg_copy, &have_cfg)) {
                            target_assoc = establish_udp_associate_with_config(&cfg_copy);
                            BOOL gated = udp_assoc_backoff_note(proxy_id, target_assoc != NULL);
                            if (target_assoc) {
                                EnterCriticalSection(&lock_udp);
                                target_assoc->next = udp_associations;
                                udp_associations = target_assoc;
                                LeaveCriticalSection(&lock_udp);
                            } else if (gated) {
                                log_message("UDP relay: UDP ASSOCIATE failed (proxy id %u, %s:%u) - retry held for the backoff window", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            } else {
                                log_message("UDP relay: UDP ASSOCIATE failed (proxy id %u, %s:%u) - retrying on the next datagram", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            }
                        } else if (!have_cfg) {
                            log_message("UDP relay: no usable proxy config (proxy id %u)", proxy_id);
                        }
                    }

                    // [Added] Drop a silent association BEFORE handing it this
                    // datagram: the relay port dies without any socket error, so
                    // silence is the only signal (see UDP_ASSOC_RX_SILENCE_MS).
                    // Dropping frees the pointer, so it must not be used below.
                    if (target_assoc != NULL && udp_assoc_is_silent(target_assoc, GetTickCount())) {
                        log_message("UDP relay: no reply for %lu ms after %lu datagrams - dropping association (proxy id %u) so the next datagram re-dials it",
                            (unsigned long)(GetTickCount() - target_assoc->last_rx),
                            (unsigned long)target_assoc->tx_since_rx, proxy_id);
                        udp_assoc_drop(proxy_id);
                        target_assoc = NULL;
                    }

                    if (target_assoc) {
                        send_buf[0]=0; send_buf[1]=0; send_buf[2]=0; send_buf[3]=SOCKS5_ATYP_IPV4;
                        memcpy(&send_buf[4], dest_addr, 4);
                        *(UINT16*)&send_buf[8] = htons(dest_port);
                        memcpy(&send_buf[10], recv_buf, recv_len);
                        if (sendto(target_assoc->udp_socket, (char*)send_buf, 10 + recv_len, 0,
                            (struct sockaddr *)&target_assoc->relay_addr, sizeof(target_assoc->relay_addr)) == SOCKET_ERROR) {
                            // Most sendto failures on a UDP socket are transient
                            // and per-destination (WSAENOBUFS under a burst, a
                            // momentary route blip). Dropping on the FIRST error
                            // converted one lost datagram into a full re-dial for
                            // every UDP flow on this proxy. Only a sustained run
                            // means the relay is really gone.
                            LONG err = WSAGetLastError();
                            target_assoc->send_fail_streak++;
                            if (target_assoc->send_fail_streak >= UDP_ASSOC_SEND_FAIL_MAX) {
                                log_message("UDP relay: sendto proxy failed %lu times in a row, last error=%ld - dropping association", (unsigned long)target_assoc->send_fail_streak, err);
                                udp_assoc_drop(proxy_id);
                            } else if (target_assoc->send_fail_streak == 1) {
                                log_message("UDP relay: sendto proxy failed, error=%ld - keeping association", err);
                            }
                        } else {
                            target_assoc->send_fail_streak = 0;
                            target_assoc->last_activity = GetTickCount();
                            // Sent, but possibly into a dead relay port - the
                            // silence check above needs this to know how much
                            // traffic has gone unanswered.
                            target_assoc->tx_since_rx++;
                        }
                    }
                }
            }
          }
        }

        // Local Apps (IPv6) -> Relay
        if (udp_relay_socket6 != INVALID_SOCKET && FD_ISSET(udp_relay_socket6, &read_fds)) {
          for (int _drain = 0; _drain < UDP_RELAY_DRAIN_MAX; _drain++) {
            if (_drain > 0 && !udp_socket_has_pending(udp_relay_socket6)) break;
            from_len = sizeof(from_addr6);
            recv_len = recvfrom(udp_relay_socket6, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr6, &from_len);
            if (recv_len <= 0) break;
            {   // bare block: keeps the original body indentation after the change
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
                        if (udp_assoc_backoff_allow(proxy_id, &cfg_copy, &have_cfg)) {
                            target_assoc = establish_udp_associate_with_config(&cfg_copy);
                            BOOL gated = udp_assoc_backoff_note(proxy_id, target_assoc != NULL);
                            if (target_assoc) {
                                EnterCriticalSection(&lock_udp);
                                target_assoc->next = udp_associations;
                                udp_associations = target_assoc;
                                LeaveCriticalSection(&lock_udp);
                            } else if (gated) {
                                log_message("UDP relay: UDP ASSOCIATE failed (IPv6, proxy id %u, %s:%u) - retry held for the backoff window", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            } else {
                                log_message("UDP relay: UDP ASSOCIATE failed (IPv6, proxy id %u, %s:%u) - retrying on the next datagram", proxy_id, cfg_copy.proxy_ip, cfg_copy.proxy_port);
                            }
                        } else if (!have_cfg) {
                            log_message("UDP relay: no usable proxy config (IPv6, proxy id %u)", proxy_id);
                        }
                    }

                    // See the IPv4 branch above: silence is the only signal that
                    // a SOCKS5 UDP relay port has stopped forwarding.
                    if (target_assoc != NULL && udp_assoc_is_silent(target_assoc, GetTickCount())) {
                        log_message("UDP relay: no reply for %lu ms after %lu datagrams (IPv6) - dropping association (proxy id %u) so the next datagram re-dials it",
                            (unsigned long)(GetTickCount() - target_assoc->last_rx),
                            (unsigned long)target_assoc->tx_since_rx, proxy_id);
                        udp_assoc_drop(proxy_id);
                        target_assoc = NULL;
                    }

                    if (target_assoc) {
                        send_buf[0]=0; send_buf[1]=0; send_buf[2]=0; send_buf[3]=SOCKS5_ATYP_IPV6;
                        memcpy(&send_buf[4], dest_addr, 16);
                        *(UINT16*)&send_buf[20] = htons(dest_port);
                        memcpy(&send_buf[22], recv_buf, recv_len);
                        if (sendto(target_assoc->udp_socket, (char*)send_buf, 22 + recv_len, 0,
                            (struct sockaddr *)&target_assoc->relay_addr, sizeof(target_assoc->relay_addr)) == SOCKET_ERROR) {
                            // See the IPv4 branch above: a transient per-destination
                            // error must not tear down every flow on this proxy.
                            LONG err = WSAGetLastError();
                            target_assoc->send_fail_streak++;
                            if (target_assoc->send_fail_streak >= UDP_ASSOC_SEND_FAIL_MAX) {
                                log_message("UDP relay: sendto proxy failed (IPv6) %lu times in a row, last error=%ld - dropping association", (unsigned long)target_assoc->send_fail_streak, err);
                                udp_assoc_drop(proxy_id);
                            } else if (target_assoc->send_fail_streak == 1) {
                                log_message("UDP relay: sendto proxy failed (IPv6), error=%ld - keeping association", err);
                            }
                        } else {
                            target_assoc->send_fail_streak = 0;
                            target_assoc->last_activity = GetTickCount();
                            target_assoc->tx_since_rx++;
                        }
                    }
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
              for (int _drain = 0; _drain < UDP_RELAY_DRAIN_MAX; _drain++) {
                if (_drain > 0 && !udp_socket_has_pending(curr->udp_socket)) break;
                from_len = sizeof(from_addr);
                recv_len = recvfrom(curr->udp_socket, (char*)recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from_addr, &from_len);
                if (recv_len <= 0) break;
                if (recv_len > 10 && recv_buf[2] == 0 && recv_buf[3] == SOCKS5_ATYP_IPV4) {
                    curr->last_activity = GetTickCount();
                    // Any well-formed reply proves the relay port still forwards,
                    // even when it maps to no tracked flow. This is the only
                    // evidence the liveness check ever gets.
                    curr->last_rx = curr->last_activity;
                    curr->tx_since_rx = 0;
                    curr->rx_seen = TRUE;
                    UINT16 src_port = ntohs(*(UINT16*)&recv_buf[8]);
                    UINT8 app_addr[16] = {0};
                    UINT16 app_port = 0;
                    BOOL exact = FALSE;

                    if (resolve_udp_response(AF_INET, &recv_buf[4], src_port,
                                             app_addr, &app_port, &exact)) {
                        if (!exact) {
                            // Answered from a different address than the one we
                            // sent to (load-balanced / anycast backend). The port
                            // match is enough to place it, but leave a trace -
                            // this reply used to be dropped outright.
                            log_message("UDP relay: response from unexpected address %u.%u.%u.%u:%u - matched by port",
                                recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7], src_port);
                        }
                        struct sockaddr_in target_addr;
                        memset(&target_addr, 0, sizeof(target_addr));
                        target_addr.sin_family = AF_INET;
                        memcpy(&target_addr.sin_addr.s_addr, app_addr, 4);
                        target_addr.sin_port = htons(app_port);
                        sendto(udp_relay_socket, (char*)&recv_buf[10], recv_len - 10, 0,
                            (struct sockaddr *)&target_addr, sizeof(target_addr));
                    } else {
                        log_message("UDP relay: response no matching connection (%u.%u.%u.%u:%u)",
                            recv_buf[4], recv_buf[5], recv_buf[6], recv_buf[7], src_port);
                    }
                }
                // SOCKS5 UDP header for IPv6: 4 (RSV/FRAG/ATYP) + 16 (addr) + 2 (port) = 22
                else if (recv_len > 22 && recv_buf[2] == 0 && recv_buf[3] == SOCKS5_ATYP_IPV6) {
                    curr->last_activity = GetTickCount();
                    curr->last_rx = curr->last_activity;
                    curr->tx_since_rx = 0;
                    curr->rx_seen = TRUE;
                    UINT16 src_port = ntohs(*(UINT16*)&recv_buf[20]);
                    UINT8 app_addr[16] = {0};
                    UINT16 app_port = 0;
                    BOOL exact = FALSE;

                    if (resolve_udp_response(AF_INET6, &recv_buf[4], src_port,
                                             app_addr, &app_port, &exact)) {
                        if (!exact) {
                            log_message("UDP relay: response from unexpected address (IPv6, port %u) - matched by port",
                                src_port);
                        }
                        if (udp_relay_socket6 != INVALID_SOCKET) {
                            struct sockaddr_in6 target_addr6;
                            memset(&target_addr6, 0, sizeof(target_addr6));
                            target_addr6.sin6_family = AF_INET6;
                            memcpy(&target_addr6.sin6_addr, app_addr, 16);
                            target_addr6.sin6_port = htons(app_port);
                            sendto(udp_relay_socket6, (char*)&recv_buf[22], recv_len - 22, 0,
                                (struct sockaddr *)&target_addr6, sizeof(target_addr6));
                        }
                    } else {
                        log_message("UDP relay: response no matching connection (IPv6, port %u)", src_port);
                    }
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