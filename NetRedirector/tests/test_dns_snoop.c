// --- test_dns_snoop.c: DNS 嗅探 (wildcard-subdomain 匹配) ---
#include "test_framework.h"
#include "NR_Utils.h"

// 合成一個 DNS 回應封包:
//   查詢 mail.google.com (A) -> 1.2.3.4
// header: ID=0xBEEF, flags=0x8180 (QR=1), QD=1, AN=1, NS=0, AR=0
// question: QNAME mail.google.com + QTYPE A + QCLASS IN
// answer  : NAME 用壓縮指標 0xC00C 指向 question name + A 1.2.3.4
static const UINT8 dns_resp[] = {
    // header (12 bytes)
    0xBE, 0xEF, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // QNAME: mail(4).google(6).com(3).root
    0x04, 'm', 'a', 'i', 'l',
    0x06, 'g', 'o', 'o', 'g', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00,
    // QTYPE A, QCLASS IN
    0x00, 0x01, 0x00, 0x01,
    // answer: NAME ptr->0x0C, TYPE A, CLASS IN, TTL 60, RDLEN 4, RDATA 1.2.3.4
    0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
    0x01, 0x02, 0x03, 0x04,
};

// 合成 AAAA 回應: 查詢 v6.example.com -> AAAA 2001:db8::1
static const UINT8 dns_resp_aaaa[] = {
    // header (12 bytes)
    0xCA, 0xFE, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    // QNAME: v6(2).example(7).com(3).root
    0x02, 'v', '6',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00,
    // QTYPE AAAA(28), QCLASS IN
    0x00, 0x1C, 0x00, 0x01,
    // answer: NAME ptr->0x0C, TYPE AAAA, CLASS IN, TTL 60, RDLEN 16
    0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10,
    // RDATA 2001:db8::1
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static const UINT8 v6_2001_db8_1[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};
static const UINT8 v6_2001_db8_2[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
};

int main(void)
{
    init_locks();

    // resolve_hostname6 (via force_resolve_rule_host6) uses getaddrinfo,
    // which requires Winsock to be initialized.
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    UINT32 ip_1234 = parse_ipv4("1.2.3.4");   // 0x04030201 (network byte order as UINT32)

    printf("== parse_ipv4 sanity ==\n");
    CHECK(ip_1234 == 0x04030201, "parse_ipv4('1.2.3.4') == 0x04030201");

    printf("== dns_snoop_parse_response ==\n");
    clear_dns_snoop_cache();

    CHECK(dns_snoop_parse_response(dns_resp, sizeof(dns_resp)) == 1,
        "synthetic response -> 1 A record");
    CHECK(dns_snoop_parse_response(NULL, sizeof(dns_resp)) == -1,
        "NULL msg -> -1");
    CHECK(dns_snoop_parse_response(dns_resp, 5) == -1,
        "short (<12) msg -> -1");

    // QR=0 (query, not response) -> -1
    {
        UINT8 query[32];
        memcpy(query, dns_resp, sizeof(query));
        query[2] = 0x01;  // clear QR bit (0x8180 -> 0x0180)
        CHECK(dns_snoop_parse_response(query, sizeof(query)) == -1,
            "QR=0 (query) -> -1");
    }

    // qdcount=0 -> -1
    {
        UINT8 noq[32];
        memcpy(noq, dns_resp, sizeof(noq));
        noq[4] = 0x00; noq[5] = 0x00;  // QDCOUNT = 0
        CHECK(dns_snoop_parse_response(noq, sizeof(noq)) == -1,
            "qdcount=0 -> -1");
    }

    printf("== dns_snoop_matches_suffix (via parse) ==\n");
    // parse 已把 1.2.3.4 -> mail.google.com 寫入快取
    CHECK(dns_snoop_matches_suffix(ip_1234, "google.com") == TRUE,
        "1.2.3.4 matches *.google.com (mail.google.com)");
    CHECK(dns_snoop_matches_suffix(ip_1234, "mail.google.com") == TRUE,
        "1.2.3.4 matches *.mail.google.com (exact)");
    CHECK(dns_snoop_matches_suffix(ip_1234, "example.com") == FALSE,
        "1.2.3.4 does not match *.example.com");
    CHECK(dns_snoop_matches_suffix(parse_ipv4("9.9.9.9"), "google.com") == FALSE,
        "9.9.9.9 (not mapped) does not match *.google.com");
    CHECK(dns_snoop_matches_suffix(ip_1234, NULL) == FALSE,
        "NULL suffix -> FALSE");
    CHECK(dns_snoop_matches_suffix(ip_1234, "") == FALSE,
        "empty suffix -> FALSE");

    printf("== dns_snoop_record / matches_suffix (direct, case-insensitive) ==\n");
    clear_dns_snoop_cache();
    dns_snoop_record(ip_1234, "a.b.Google.Com");
    CHECK(dns_snoop_matches_suffix(ip_1234, "google.com") == TRUE,
        "record 'a.b.Google.Com' matches *.google.com (case-insensitive)");
    CHECK(dns_snoop_matches_suffix(ip_1234, "b.google.com") == TRUE,
        "matches *.b.google.com (sub-subdomain)");

    printf("== match_ip_pattern integration (snoop cache) ==\n");
    clear_dns_cache();
    clear_dns_snoop_cache();
    dns_snoop_record(ip_1234, "docs.google.com");
    CHECK(match_ip_pattern("*.google.com", ip_1234) == TRUE,
        "match_ip_pattern('*.google.com', 1.2.3.4) via snoop");
    CHECK(match_ip_pattern("*.google.com", parse_ipv4("9.9.9.9")) == FALSE,
        "match_ip_pattern('*.google.com', 9.9.9.9) miss");
    // 裸域名 (無 *.) 只比 apex 解析 IP; 此處未解析 apex -> 不中
    CHECK(match_ip_pattern("google.com", ip_1234) == FALSE,
        "bare 'google.com' does not match a subdomain IP (apex-only)");

    printf("== clear_dns_snoop_cache ==\n");
    clear_dns_snoop_cache();
    CHECK(dns_snoop_matches_suffix(ip_1234, "google.com") == FALSE,
        "after clear, snoop cache miss");

    printf("== dns_snoop_parse_response (AAAA) ==\n");
    CHECK(dns_snoop_parse_response(dns_resp_aaaa, sizeof(dns_resp_aaaa)) == 1,
        "AAAA response -> 1 record");
    CHECK(dns_snoop_matches_suffix6(v6_2001_db8_1, "example.com") == TRUE,
        "2001:db8::1 matches *.example.com (v6.example.com)");

    printf("== match_ip_pattern6 (wildcard via snoop) ==\n");
    CHECK(match_ip_pattern6("*.example.com", v6_2001_db8_1) == TRUE,
        "match_ip_pattern6('*.example.com', 2001:db8::1) via snoop");
    CHECK(match_ip_pattern6("*.example.com", v6_2001_db8_2) == FALSE,
        "match_ip_pattern6('*.example.com', 2001:db8::2) miss");
    CHECK(match_ip_pattern6("google.com", v6_2001_db8_1) == FALSE,
        "bare IPv6 domain without primed cache -> no match");

    printf("== match_ip_pattern6 (literal) ==\n");
    CHECK(match_ip_pattern6("2001:db8::1", v6_2001_db8_1) == TRUE,
        "IPv6 literal exact match");
    CHECK(match_ip_pattern6("*", v6_2001_db8_1) == TRUE,
        "IPv6 '*' wildcard");

    printf("== match_ip_pattern6 (IPv6 apex resolution) ==\n");
    {
        static const UINT8 v6_loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        force_resolve_rule_host6("localhost");
        UINT8 got[16];
        CHECK(resolve_rule_host_cached6("localhost", got) == TRUE,
            "localhost resolves via IPv6 (cached)");
        CHECK(match_ip_pattern6("localhost", v6_loopback) == TRUE,
            "bare IPv6 domain 'localhost' matches ::1");
        CHECK(match_ip_pattern6("*.localhost", v6_loopback) == TRUE,
            "'*.localhost' falls back to apex resolution for ::1");
        force_resolve_rule_host6("no-such-v6-host-zzz.invalid");
        CHECK(match_ip_pattern6("no-such-v6-host-zzz.invalid", v6_loopback) == FALSE,
            "unresolvable IPv6 domain -> no match");
    }

    return test_summary("test_dns_snoop");
}
