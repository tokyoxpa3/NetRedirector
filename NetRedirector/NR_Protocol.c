// --- START OF FILE NR_Protocol.c ---
#include "NR_Protocol.h"

int recv_n(SOCKET s, unsigned char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}

int socks5_connect_with_config(SOCKET s, int family, const UINT8 *dest_addr, UINT16 dest_port, const PROXY_CONFIG* proxy_config)
{
    // Auth sub-negotiation needs 3 + 255 (user) + 255 (pass) = 513 bytes max
    unsigned char buf[600];
    int len;
    BOOL use_auth = (proxy_config != NULL && proxy_config->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 0x02; // Methods count
        buf[2] = SOCKS5_AUTH_NONE;
        buf[3] = 0x02; // User/Pass
        if (send(s, (char*)buf, 4, 0) != 4) return -1;
    } else {
        buf[1] = 0x01;
        buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3) return -1;
    }

    if (recv_n(s, buf, 2) != 0) return -1;
    if (buf[0] != SOCKS5_VERSION) return -1;

    // Handle Auth
    if (buf[1] == 0x02) {
        if (!use_auth) return -1;
        size_t user_len = strlen(proxy_config->username);
        size_t pass_len = strlen(proxy_config->password);
        if (user_len > 255 || pass_len > 255 ||
            3 + user_len + pass_len > sizeof(buf)) return -1;

        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], proxy_config->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], proxy_config->password, pass_len);

        if (send(s, (char*)buf, (int)(3 + user_len + pass_len), 0) != (int)(3 + user_len + pass_len)) return -1;

        if (recv_n(s, buf, 2) != 0) return -1;
        if (buf[0] != 0x01 || buf[1] != 0x00) return -1; // Auth failed
    } else if (buf[1] != SOCKS5_AUTH_NONE) {
        return -1;
    }

    // Send Connect Command.
    // Remote DNS (socks5h): when the proxy is configured to resolve names and
    // the DNS snoop cache knows the hostname behind this IP, send ATYP_DOMAIN
    // so the proxy resolves it (geo-correct CDN routing, no local DNS leak).
    // Falls back to the IP when no hostname is known.
    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_CONNECT;
    buf[2] = 0x00;

    char domain[256];
    size_t dlen = 0;
    if (proxy_config != NULL && proxy_config->send_domain_to_proxy &&
        dns_snoop_lookup_domain(family, dest_addr, domain, sizeof(domain))) {
        dlen = strlen(domain);
    }

    if (dlen > 0 && dlen <= 255) {
        buf[3] = SOCKS5_ATYP_DOMAIN;
        buf[4] = (unsigned char)dlen;
        memcpy(&buf[5], domain, dlen);
        buf[5 + dlen] = (dest_port >> 8) & 0xFF;
        buf[6 + dlen] = (dest_port >> 0) & 0xFF;
        len = (int)(7 + dlen);
    } else if (family == AF_INET6) {
        buf[3] = SOCKS5_ATYP_IPV6;
        memcpy(&buf[4], dest_addr, 16);
        buf[20] = (dest_port >> 8) & 0xFF;
        buf[21] = (dest_port >> 0) & 0xFF;
        len = 22;
    } else {
        buf[3] = SOCKS5_ATYP_IPV4;
        memcpy(&buf[4], dest_addr, 4);
        buf[8] = (dest_port >> 8) & 0xFF;
        buf[9] = (dest_port >> 0) & 0xFF;
        len = 10;
    }

    if (send(s, (char*)buf, len, 0) != len) return -1;

    // Read reply (variable length based on ATYP)
    if (recv_n(s, buf, 4) != 0) return -1;
    if (buf[0] != SOCKS5_VERSION || buf[1] != 0x00) return -1;

    int reply_rest = 2;
    if (buf[3] == SOCKS5_ATYP_IPV4) reply_rest += 4;
    else if (buf[3] == SOCKS5_ATYP_IPV6) reply_rest += 16;
    else if (buf[3] == 0x03) reply_rest += 1;
    if (recv_n(s, buf, reply_rest) != 0) return -1;
    if (buf[3] == 0x03) {
        // Domain name: variable length
        int name_len = buf[4];
        if (recv_n(s, buf, name_len + 2) != 0) return -1;
    }

    return 0;
}

int http_connect_with_config(SOCKET s, int family, const UINT8 *dest_addr, UINT16 dest_port, const PROXY_CONFIG* proxy_config)
{
    char request[1024];
    char response[4096];
    int len;
    BOOL use_auth = (proxy_config != NULL && proxy_config->username[0] != '\0');

    char host_str[300];
    char domain[256];
    if (proxy_config != NULL && proxy_config->send_domain_to_proxy &&
        dns_snoop_lookup_domain(family, dest_addr, domain, sizeof(domain))) {
        // Remote DNS: CONNECT to the hostname so the proxy resolves it.
        snprintf(host_str, sizeof(host_str), "%s:%u", domain, dest_port);
    } else if (family == AF_INET6) {
        char ip6[MAX_IP_STR];
        addr_to_string(AF_INET6, dest_addr, ip6, sizeof(ip6));
        snprintf(host_str, sizeof(host_str), "[%s]:%u", ip6, dest_port);
    } else {
        char ip4[MAX_IP_STR];
        addr_to_string(AF_INET, dest_addr, ip4, sizeof(ip4));
        snprintf(host_str, sizeof(host_str), "%s:%u", ip4, dest_port);
    }

    if (use_auth) {
        char credentials[600];  // 255 (user) + ':' + 255 (pass) + NUL = 512+ needed
        char encoded[1024];
        snprintf(credentials, sizeof(credentials), "%s:%s", proxy_config->username, proxy_config->password);
        base64_encode(credentials, encoded, sizeof(encoded));

        len = snprintf(request, sizeof(request),
            "CONNECT %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_str, host_str, encoded);
    } else {
        len = snprintf(request, sizeof(request),
            "CONNECT %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_str, host_str);
    }

    if (send(s, request, len, 0) != len) return -1;
    len = recv(s, response, sizeof(response) - 1, 0);
    if (len <= 0) return -1;
    response[len] = '\0';

    if (strncmp(response, "HTTP/1.", 7) != 0) return -1;
    
    int status_code = 0;
    char *code_start = strchr(response, ' ');
    if (code_start != NULL) status_code = atoi(code_start + 1);

    if (status_code != 200) return -1;
    return 0;
}

int socks5_udp_associate_with_config(SOCKET s, struct sockaddr_in *relay_addr, const PROXY_CONFIG* proxy_config)
{
    // Auth sub-negotiation needs 3 + 255 (user) + 255 (pass) = 513 bytes max
    unsigned char buf[600];
    BOOL use_auth = (proxy_config != NULL && proxy_config->username[0] != '\0');

    buf[0] = SOCKS5_VERSION;
    if (use_auth) {
        buf[1] = 0x02; buf[2] = SOCKS5_AUTH_NONE; buf[3] = 0x02;
        if (send(s, (char*)buf, 4, 0) != 4) return -1;
    } else {
        buf[1] = 0x01; buf[2] = SOCKS5_AUTH_NONE;
        if (send(s, (char*)buf, 3, 0) != 3) return -1;
    }

    if (recv_n(s, buf, 2) != 0 || buf[0] != SOCKS5_VERSION) return -1;

    if (buf[1] == 0x02) {
        if (!use_auth) return -1;
        size_t user_len = strlen(proxy_config->username);
        size_t pass_len = strlen(proxy_config->password);
        if (user_len > 255 || pass_len > 255 ||
            3 + user_len + pass_len > sizeof(buf)) return -1;
        buf[0] = 0x01;
        buf[1] = (unsigned char)user_len;
        memcpy(&buf[2], proxy_config->username, user_len);
        buf[2 + user_len] = (unsigned char)pass_len;
        memcpy(&buf[3 + user_len], proxy_config->password, pass_len);
        if (send(s, (char*)buf, (int)(3 + user_len + pass_len), 0) != (int)(3 + user_len + pass_len)) return -1;
        if (recv_n(s, buf, 2) != 0 || buf[0] != 0x01 || buf[1] != 0x00) return -1;
    } else if (buf[1] != SOCKS5_AUTH_NONE) return -1;

    buf[0] = SOCKS5_VERSION;
    buf[1] = SOCKS5_CMD_UDP_ASSOCIATE;
    buf[2] = 0x00;
    buf[3] = SOCKS5_ATYP_IPV4;
    memset(&buf[4], 0, 6); // 0.0.0.0:0
    if (send(s, (char*)buf, 10, 0) != 10) return -1;

    // 完整讀取回覆 (TCP 為串流，裸 recv 可能只收到部分資料)
    if (recv_n(s, buf, 4) != 0 || buf[0] != SOCKS5_VERSION || buf[1] != 0x00) return -1;
    if (buf[3] != SOCKS5_ATYP_IPV4) return -1;
    if (recv_n(s, buf + 4, 6) != 0) return -1;

    relay_addr->sin_family = AF_INET;
    relay_addr->sin_addr.s_addr = *(UINT32*)&buf[4];
    relay_addr->sin_port = *(UINT16*)&buf[8];

    return 0;
}

UDP_ASSOCIATION* establish_udp_associate_with_config(const PROXY_CONFIG* proxy_config)
{
    if (proxy_config == NULL || proxy_config->proxy_type != PROXY_TYPE_SOCKS5) return NULL;

    SOCKET tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_sock == INVALID_SOCKET) return NULL;

    // [Fixed] Was timeout = 0 (infinite): a dead SOCKS5 proxy parked the relay
    // thread forever in the handshake recv(). Bounded to UDP_ASSOC_TIMEOUT_MS
    // (short, because this dial runs on the single UDP relay thread and stalls
    // every other proxied UDP flow while it blocks); the control socket is only
    // select()'d for readability later, so the timeout cannot drop an
    // established association.
    DWORD timeout = UDP_ASSOC_TIMEOUT_MS;
    setsockopt(tcp_sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(tcp_sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    struct sockaddr_in socks_addr;
    memset(&socks_addr, 0, sizeof(socks_addr));
    socks_addr.sin_family = AF_INET;
    socks_addr.sin_addr.s_addr = resolve_hostname(proxy_config->proxy_ip);
    socks_addr.sin_port = htons(proxy_config->proxy_port);

    // �p�G�ѪR���� (0)�A������^
    if (socks_addr.sin_addr.s_addr == 0) {
        closesocket(tcp_sock);
        return NULL;
    }

    // [Fixed] Bounded connect (blocking connect burns ~21 s on SYN retries)
    if (!connect_with_timeout(tcp_sock, (struct sockaddr *)&socks_addr, sizeof(socks_addr), UDP_ASSOC_TIMEOUT_MS)) {
        closesocket(tcp_sock);
        return NULL;
    }

    EnableKeepAlive(tcp_sock);

    struct sockaddr_in relay_addr;
    if (socks5_udp_associate_with_config(tcp_sock, &relay_addr, proxy_config) != 0) {
        closesocket(tcp_sock);
        return NULL;
    }

    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        closesocket(tcp_sock);
        return NULL;
    }

    // This single socket carries every proxied UDP flow for this proxy, so a
    // burst (game map load, QUIC ramp-up) can overflow the default receive
    // buffer and drop datagrams before the relay thread drains them.
    int udp_buf = UDP_SOCK_BUF_BYTES;
    setsockopt(udp_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&udp_buf, sizeof(udp_buf));
    setsockopt(udp_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&udp_buf, sizeof(udp_buf));
    // A dead destination behind the proxy must not abort the relay's drain loop
    // with WSAECONNRESET; this socket carries every UDP flow for this proxy.
    disable_udp_connreset(udp_sock);

    UDP_ASSOCIATION* assoc = (UDP_ASSOCIATION*)malloc(sizeof(UDP_ASSOCIATION));
    if (assoc == NULL) {
        closesocket(tcp_sock);
        closesocket(udp_sock);
        return NULL;
    }

    assoc->proxy_id = proxy_config->proxy_id;
    assoc->control_socket = tcp_sock;
    assoc->udp_socket = udp_sock;
    assoc->relay_addr = relay_addr;
    assoc->last_activity = GetTickCount();
    assoc->send_fail_streak = 0;
    // Silence tracking starts at establish time: a relay that never forwards
    // must still be re-dialed eventually (see UDP_ASSOC_RX_SILENCE_MS).
    assoc->last_rx = assoc->last_activity;
    assoc->tx_since_rx = 0;
    assoc->rx_seen = FALSE;
    assoc->next = NULL;

    log_message("UDP ASSOCIATE established with SOCKS5 proxy ID %u (%s:%d)", assoc->proxy_id, proxy_config->proxy_ip, proxy_config->proxy_port);
    return assoc;
}