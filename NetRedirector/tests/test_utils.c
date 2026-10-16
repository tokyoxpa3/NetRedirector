// --- TEMPORARY-ISH test: NR_Utils 純函式 (字串/位址/比對) ---
#include "test_framework.h"
#include "NR_Utils.h"

int main(void)
{
    init_locks();

    // getaddrinfo() (used by resolve_rule_host / resolve_hostname for real
    // hostnames) requires Winsock to be initialized.
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    printf("== parse_ipv4 ==\n");
    CHECK(parse_ipv4("192.168.1.1") == 0x0101A8C0, "192.168.1.1 -> 0x0101A8C0");
    CHECK(parse_ipv4("127.0.0.1") == 0x0100007F, "127.0.0.1 -> 0x0100007F");
    CHECK(parse_ipv4("") == 0, "empty -> 0");
    CHECK(parse_ipv4("abc") == 0, "abc -> 0");
    CHECK(parse_ipv4("999.1.1.1") == 0, "999.1.1.1 -> 0 (octet >255)");
    CHECK(parse_ipv4("1.2.3") == 0, "1.2.3 -> 0");

    printf("== resolve_hostname (IP only) ==\n");
    CHECK(resolve_hostname("127.0.0.1") == 0x0100007F, "127.0.0.1 resolves");
    CHECK(resolve_hostname("") == 0, "empty -> 0");
    CHECK(resolve_hostname(NULL) == 0, "NULL -> 0");

    printf("== base64_encode ==\n");
    {
        char out[64];
        base64_encode("test", out, sizeof(out));
        CHECK(strcmp(out, "dGVzdA==") == 0, "'test' -> dGVzdA==");
        base64_encode("", out, sizeof(out));
        CHECK(strcmp(out, "") == 0, "'' -> ''");
        base64_encode("hello world", out, sizeof(out));
        CHECK(strcmp(out, "aGVsbG8gd29ybGQ=") == 0, "'hello world' correct");
    }

    printf("== extract_filename ==\n");
    CHECK(strcmp(extract_filename("C:\\dir\\app.exe"), "app.exe") == 0, "path -> app.exe");
    CHECK(strcmp(extract_filename("app.exe"), "app.exe") == 0, "bare -> app.exe");
    CHECK(strcmp(extract_filename(""), "") == 0, "empty -> ''");

    printf("== is_broadcast_or_multicast ==\n");
    CHECK(is_broadcast_or_multicast(0xFFFFFFFF) == TRUE, "255.255.255.255 -> TRUE");
    CHECK(is_broadcast_or_multicast(0x0100007F) == TRUE, "127.0.0.1 -> TRUE");
    CHECK(is_broadcast_or_multicast(0x010000E0) == TRUE, "224.0.0.1 -> TRUE");
    CHECK(is_broadcast_or_multicast(0x08080808) == FALSE, "8.8.8.8 -> FALSE");

    printf("== is_wildcard_str ==\n");
    CHECK(is_wildcard_str("*") == TRUE, "ASCII * -> TRUE");
    CHECK(is_wildcard_str("ANY") == TRUE, "ANY -> TRUE");
    CHECK(is_wildcard_str("\xEF\xBC\x8A") == TRUE, "full-width ＊ -> TRUE");
    CHECK(is_wildcard_str("fire*") == FALSE, "fire* -> FALSE (含字首, 非純萬用)");
    CHECK(is_wildcard_str(NULL) == FALSE, "NULL -> FALSE");

    printf("== match_ip_pattern ==\n");
    CHECK(match_ip_pattern("*", 0x08080808) == TRUE, "'*' matches any");
    CHECK(match_ip_pattern("8.8.8.8", 0x08080808) == TRUE, "exact match");
    CHECK(match_ip_pattern("1.2.*.4", 0x04050201) == TRUE, "octet wildcard match");
    CHECK(match_ip_pattern("1.2.3.4", 0x08080808) == FALSE, "mismatch");

    printf("== match_ip_pattern (domain rules) ==\n");
    // [Modified] 封包執行緒的比對路徑現在只讀快取 (絕不呼叫 getaddrinfo):
    // 先用 resolve_rule_host / refresh_rule_dns 把快取填好再比對。
    CHECK(resolve_rule_host("localhost") == 0x0100007F, "resolve_rule_host('localhost') resolves");
    CHECK(resolve_rule_host("localhost") == 0x0100007F, "resolve_rule_host cached (2nd call)");
    CHECK(match_ip_pattern("localhost", 0x0100007F) == TRUE, "primed 'localhost' matches 127.0.0.1");
    CHECK(match_ip_pattern("*.localhost", 0x0100007F) == TRUE, "'*.localhost' -> strip '*.' -> same cache key");
    CHECK(match_ip_pattern("localhost", 0x08080808) == FALSE, "'localhost' != 8.8.8.8");
    CHECK(match_ip_pattern("*.8.8.8.8", 0x08080808) == TRUE, "'*.8.8.8.8' still octet wildcard (IP-like)");
    CHECK(resolve_rule_host("no-such-host-zzz.invalid") == 0, "unresolvable domain -> resolve fails");
    CHECK(match_ip_pattern("no-such-host-zzz.invalid", 0x08080808) == FALSE, "cached failure -> no match");

    clear_dns_cache();
    CHECK(match_ip_pattern("localhost", 0x0100007F) == FALSE, "cache miss -> no match (match path never resolves)");
    CHECK(resolve_rule_host_cached("localhost") == 0, "resolve_rule_host_cached after clear -> miss");
    refresh_rule_dns("*.localhost; 8.8.8.8; *");   // 只應解析 localhost (其餘為 IP/萬用)
    CHECK(match_ip_pattern("localhost", 0x0100007F) == TRUE, "refresh_rule_dns re-primes the cache");
    CHECK(resolve_rule_host_cached("localhost") == 0x0100007F, "force-resolve stored the entry");

    printf("== match_port_pattern ==\n");
    CHECK(match_port_pattern("*", 12345) == TRUE, "'*' matches");
    CHECK(match_port_pattern("443", 443) == TRUE, "exact");
    CHECK(match_port_pattern("8000-9000", 8500) == TRUE, "range inside");
    CHECK(match_port_pattern("8000-9000", 7999) == FALSE, "range below");
    CHECK(match_port_pattern("80;443", 443) == FALSE, "';' 非分隔 (port 用 ',')");

    printf("== match_ip_list / match_port_list ==\n");
    CHECK(match_ip_list("1.2.3.4;8.8.8.8", 0x08080808) == TRUE, "ip list match");
    CHECK(match_ip_list("1.2.3.4;8.8.8.8", 0x01010101) == FALSE, "ip list miss");
    CHECK(match_port_list("80,443", 443) == TRUE, "port list match");
    CHECK(match_port_list("80,443", 8080) == FALSE, "port list miss");

    printf("== match_ip_pattern6 (IPv6 CIDR) ==\n");
    {
        // 2001:db8::1, 2001:db9::1, 2001:db8:1234::1 - network byte order.
        UINT8 a_db8[16]      = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1};
        UINT8 a_db8_zero[16] = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        UINT8 a_db9[16]      = {0x20,0x01,0x0d,0xb9, 0,0,0,0, 0,0,0,0, 0,0,0,1};
        UINT8 a_db8_1234[16] = {0x20,0x01,0x0d,0xb8, 0x12,0x34,0,0, 0,0,0,0, 0,0,0,1};

        CHECK(match_ip_pattern6("2001:db8::/32", a_db8) == TRUE, "/32 covers its own prefix");
        CHECK(match_ip_pattern6("2001:db8::/32", a_db9) == FALSE, "/32 does not cover the next /32");
        CHECK(match_ip_pattern6("2001:db8::/32", a_db8_1234) == TRUE, "/32 covers a deeper subnet");
        CHECK(match_ip_pattern6("2001:db8:1234::/48", a_db8_1234) == TRUE, "/48 matches");
        CHECK(match_ip_pattern6("2001:db8::/48", a_db8_1234) == FALSE, "/48 miss on bits 32-47");
        CHECK(match_ip_pattern6("2001:db8::/128", a_db8_zero) == TRUE, "/128 behaves as an exact match");
        CHECK(match_ip_pattern6("2001:db8::/128", a_db8) == FALSE, "/128 miss on the last bit");
        CHECK(match_ip_pattern6("::/0", a_db9) == TRUE, "/0 matches everything");
        CHECK(match_ip_pattern6("2001:db8::1", a_db8) == TRUE, "exact address still works");
        CHECK(match_ip_pattern6("2001:db8::1", a_db9) == FALSE, "exact address still rejects");

        // Malformed CIDR must not fall through to the string compare: a typo
        // has to be a non-match, not a rule that silently matches nothing.
        CHECK(match_ip_pattern6("2001:db8::/129", a_db8) == FALSE, "prefix > 128 -> FALSE");
        CHECK(match_ip_pattern6("2001:db8::/", a_db8) == FALSE, "empty prefix -> FALSE");
        CHECK(match_ip_pattern6("2001:db8::/abc", a_db8) == FALSE, "non-numeric prefix -> FALSE");
        CHECK(match_ip_pattern6("/32", a_db8) == FALSE, "empty address -> FALSE");
        CHECK(match_ip_pattern6("nope/32", a_db8) == FALSE, "unparsable address -> FALSE");
        CHECK(match_ip_pattern6("2001:db8::/32/32", a_db8) == FALSE, "two slashes -> FALSE");

        CHECK(match_ip_list6("2001:db8::/32;2001:db9::/32", a_db9) == TRUE, "list second CIDR matches");
        CHECK(match_ip_list6("2001:db8::/32", a_db9) == FALSE, "list CIDR miss");
        CHECK(match_ip_list6("2001:db8::/32", a_db8) == TRUE, "list CIDR match");
        CHECK(match_ip_pattern6("*", a_db9) == TRUE, "wildcard still wins");
        CHECK(match_ip_pattern6("ANY", a_db9) == TRUE, "'ANY' still wins");
    }

    printf("== match_process_pattern ==\n");
    CHECK(match_process_pattern("*", "C:\\x\\firefox.exe") == TRUE, "'*' matches any");
    CHECK(match_process_pattern("fire*", "firefox.exe") == TRUE, "suffix wildcard");
    CHECK(match_process_pattern("*.exe", "chrome.exe") == TRUE, "prefix wildcard");
    CHECK(match_process_pattern("fire*.exe", "firefox.exe") == TRUE, "middle wildcard");
    CHECK(match_process_pattern("chrome.exe", "firefox.exe") == FALSE, "exact mismatch");
    CHECK(match_process_pattern("C:\\Games\\*.exe", "C:\\Games\\game.exe") == TRUE, "full path pattern");

    printf("== match_process_list ==\n");
    CHECK(match_process_list("chrome.*;Game*.exe", "chrome.exe") == TRUE, "list first match");
    CHECK(match_process_list("chrome.*;Game*.exe", "Game.exe") == TRUE, "list second match");
    CHECK(match_process_list("chrome.*;Game*.exe", "firefox.exe") == FALSE, "list miss");
    CHECK(match_process_list("*", "anything.exe") == TRUE, "'*' list");

    printf("== hosts_field_has_domain ==\n");
    // Gates the OS resolver-cache flush: only rules that carry a domain token
    // depend on the DNS-snoop IP->hostname map, so only those need the flush.
    // A false positive here means a needless machine-wide DNS cache flush on
    // every rule edit; a false negative means a domain rule that silently
    // never matches.
    CHECK(hosts_field_has_domain("google.com") == TRUE, "bare domain");
    CHECK(hosts_field_has_domain("*.google.com") == TRUE, "wildcard subdomain");
    CHECK(hosts_field_has_domain("*google*") == TRUE, "generic wildcard with letters");
    CHECK(hosts_field_has_domain("8.8.8.8;example.com") == TRUE, "mixed list with a domain");
    CHECK(hosts_field_has_domain("8.8.8.8;1.1.1.1") == FALSE, "IP-only list");
    CHECK(hosts_field_has_domain("192.168.*.*") == FALSE, "IP octet wildcard is not a domain");
    CHECK(hosts_field_has_domain("2001:db8::1") == FALSE, "IPv6 literal is not a domain");
    CHECK(hosts_field_has_domain("2001:db8::/32") == FALSE, "IPv6 CIDR is not a domain");
    CHECK(hosts_field_has_domain("8.8.8.8;2001:db8::/32") == FALSE, "IPv4 + IPv6 CIDR list is not a domain");
    CHECK(hosts_field_has_domain("2001:db8::/32;example.com") == TRUE, "CIDR + domain list still has a domain");
    CHECK(hosts_field_has_domain("*") == FALSE, "'*' is not a domain");
    CHECK(hosts_field_has_domain("ANY") == FALSE, "'ANY' is not a domain");
    CHECK(hosts_field_has_domain("") == FALSE, "empty");
    CHECK(hosts_field_has_domain(NULL) == FALSE, "NULL");

    printf("== is_lan_or_on_link_address ==\n");
    {
        UINT8 a10[4] = {10, 1, 1, 1};
        UINT8 a192[4] = {192, 168, 1, 1};
        UINT8 a172[4] = {172, 16, 0, 1};
        UINT8 a8[4] = {8, 8, 8, 8};
        UINT8 a6[16] = {0xfd, 0};  // IPv6 ULA
        CHECK(is_lan_or_on_link_address(AF_INET, a10) == TRUE, "10/8 -> LAN");
        CHECK(is_lan_or_on_link_address(AF_INET, a192) == TRUE, "192.168/16 -> LAN");
        CHECK(is_lan_or_on_link_address(AF_INET, a172) == TRUE, "172.16/12 -> LAN");
        CHECK(is_lan_or_on_link_address(AF_INET, a8) == FALSE, "8.8.8.8 -> not LAN");
        CHECK(is_lan_or_on_link_address(AF_INET6, a6) == TRUE, "fd00::/8 ULA -> LAN");
    }

    return test_summary("test_utils");
}
