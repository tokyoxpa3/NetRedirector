// --- START OF FILE NR_Core.h ---
#ifndef NR_CORE_H
#define NR_CORE_H

#include "NR_Common.h"
#include "NR_State.h"
#include "NR_RuleEngine.h"
#include "NR_Protocol.h"
#include "NR_Utils.h"

// Thread Functions
// Packet pipeline: packet_threads[0] is the receiver (sole WinDivertRecv
// caller), [1..NUM_PACKET_THREADS-1] are flow workers fed by flow_hash().
DWORD WINAPI packet_receiver(LPVOID arg);
DWORD WINAPI flow_worker(LPVOID arg);
DWORD WINAPI local_proxy_server(LPVOID arg);
DWORD WINAPI udp_relay_server(LPVOID arg);
DWORD WINAPI cleanup_thread(LPVOID arg);
DWORD WINAPI connection_handler(LPVOID arg);
DWORD WINAPI transfer_handler(LPVOID arg);

// Flow dispatch queues (receiver -> workers). init before thread creation,
// shutdown only after the receiver and all workers have been joined.
BOOL flow_queues_init(void);
void flow_queues_shutdown(void);

// [Pure, host-testable] Source endpoint a packet returning from the relay must
// carry so the app sees the real remote server as the sender. Rewrites to the
// remote endpoint when known; otherwise leaves the packet's own source as-is.
// Returns TRUE when the source was rewritten.
BOOL udp_reply_source(int family,
                      const UINT8 *pkt_src_addr, UINT16 pkt_src_port,
                      BOOL have_remote, const UINT8 *remote_addr, UINT16 remote_port,
                      UINT8 *out_src_addr, UINT16 *out_src_port);

// [Pure, host-testable] TRUE when an association has sent enough datagrams and
// heard nothing back for long enough that its relay port must be presumed dead.
// The caller drops the association, so the next datagram re-dials the proxy -
// this is what keeps a silently-expired SOCKS5 UDP mapping from black-holing
// every proxied flow for hours. See UDP_ASSOC_RX_SILENCE_MS in NR_Common.h.
BOOL udp_assoc_is_silent(const UDP_ASSOCIATION *assoc, DWORD now);

// Transfer-socket registry: Stop() shuts every registered pair down so
// connection/transfer threads blocked in recv() unblock and exit. Threads
// keep ownership of closesocket() (no double-close).
BOOL register_connection_sockets(SOCKET client_socket, SOCKET proxy_socket);
void unregister_connection_sockets(SOCKET client_socket, SOCKET proxy_socket);
void shutdown_all_connections(void);

#endif // NR_CORE_H