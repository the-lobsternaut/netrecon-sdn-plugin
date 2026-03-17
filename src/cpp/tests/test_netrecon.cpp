#include "netrecon/types.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <cmath>
#include <string>
using namespace netrecon;

// Declare functions from netrecon.cpp
namespace netrecon {
    struct IPv4Addr { uint8_t octets[4]; };
    bool parseIPv4(const std::string& ip, IPv4Addr& addr);
    std::string reverseIPv4(const std::string& ip);
    std::string cymruASNQuery(const std::string& ip);
    std::string cymruASNNameQuery(uint32_t asn);
    struct CymruASNResult {
        uint32_t asn; std::string prefix; std::string country;
        std::string rir; std::string date; bool valid;
    };
    CymruASNResult parseCymruResponse(const std::string& txt);
    NetRecord asnToNetRecord(const std::string& ip, const CymruASNResult& asn_result);

    enum class DNSType : uint16_t { A=1, NS=2, CNAME=5, SOA=6, MX=15, TXT=16, AAAA=28 };
    std::vector<uint8_t> encodeDNSName(const std::string& domain);
    std::vector<uint8_t> buildDNSQuery(const std::string& domain, DNSType qtype, uint16_t id);

    struct TracerouteHop {
        int hop_number; std::string hostname; std::string ip;
        double rtt_ms[3]; int n_rtts; bool timeout;
    };
    std::vector<TracerouteHop> parseTraceroute(const std::string& output);
    std::vector<NetRecord> tracerouteToRecords(const std::vector<TracerouteHop>& hops);

    struct KnownASN { uint32_t asn; const char* org; const char* country; };
    const KnownASN* lookupKnownASN(uint32_t asn);
    void enrichWithASN(NetRecord& record);
}

void testSerialization() {
    std::vector<NetRecord> records;
    NetRecord r{};
    std::strncpy(r.domain, "example.mil", 63);
    std::strncpy(r.ip_addr, "192.168.1.1", 39);
    r.port = 443; r.record_type = static_cast<uint8_t>(RecordType::DNS_A);
    r.risk_level = static_cast<uint8_t>(RiskLevel::HIGH);
    r.infra_flags = static_cast<uint8_t>(InfraFlag::MIL) | static_cast<uint8_t>(InfraFlag::EXPIRED_CERT);
    r.asn = 12345;
    records.push_back(r);
    auto buf = serialize(records);
    assert(std::memcmp(buf.data(), "$NET", 4) == 0);
    NETHeader hdr; std::vector<NetRecord> dec;
    assert(deserialize(buf.data(), buf.size(), hdr, dec));
    assert(dec.size() == 1);
    std::cout << "  Serialization ✓\n";
}

void testFilters() {
    std::vector<NetRecord> records;
    NetRecord r1{}; r1.risk_level = 3; r1.infra_flags = 16; records.push_back(r1);
    NetRecord r2{}; r2.risk_level = 1; r2.infra_flags = 2; records.push_back(r2);
    NetRecord r3{}; r3.risk_level = 4; r3.infra_flags = 80; records.push_back(r3);
    assert(filterByRisk(records, RiskLevel::HIGH).size() == 2);
    assert(filterByFlag(records, InfraFlag::MIL).size() == 2);
    std::cout << "  Filters ✓\n";
}

// ============================================================================
// Test IP-to-ASN (Team Cymru DNS Protocol)
// ============================================================================

void testCymruASN() {
    // Test query generation for 8.8.8.8 (Google DNS)
    auto query = cymruASNQuery("8.8.8.8");
    assert(query == "8.8.8.8.origin.asn.cymru.com");

    // Test query for 1.1.1.1 (Cloudflare)
    query = cymruASNQuery("1.1.1.1");
    assert(query == "1.1.1.1.origin.asn.cymru.com");

    // Test reverse IP
    assert(reverseIPv4("8.8.8.8") == "8.8.8.8");
    assert(reverseIPv4("192.168.1.100") == "100.1.168.192");
    assert(reverseIPv4("10.0.0.1") == "1.0.0.10");

    // Test ASN name query
    auto name_query = cymruASNNameQuery(15169);
    assert(name_query == "AS15169.asn.cymru.com");

    // Test parsing Cymru response
    // 8.8.8.8 → AS15169 Google
    auto result = parseCymruResponse("15169 | 8.8.8.0/24 | US | arin | 2000-03-30");
    assert(result.valid);
    assert(result.asn == 15169);
    assert(result.prefix == "8.8.8.0/24");
    assert(result.country == "US");
    assert(result.rir == "arin");

    // Test with Cloudflare
    result = parseCymruResponse("13335 | 1.1.1.0/24 | US | arin | 2014-03-28");
    assert(result.valid);
    assert(result.asn == 13335);

    // Test building NetRecord from ASN result
    auto asn_result = parseCymruResponse("15169 | 8.8.8.0/24 | US | arin | 2000-03-30");
    auto rec = asnToNetRecord("8.8.8.8", asn_result);
    assert(rec.asn == 15169);
    assert(std::string(rec.ip_addr) == "8.8.8.8");
    assert(std::string(rec.country) == "US");

    // Invalid inputs
    assert(cymruASNQuery("not-an-ip").empty());
    assert(reverseIPv4("abc").empty());
    assert(!parseCymruResponse("garbage").valid);

    std::cout << "  Team Cymru ASN ✓ (8.8.8.8 → AS15169, query=" << query << ")\n";
}

// ============================================================================
// Test DNS Query Building
// ============================================================================

void testDNSQuery() {
    // Test DNS name encoding
    auto encoded = encodeDNSName("example.com");
    assert(encoded.size() == 13);  // \x07example\x03com\x00
    assert(encoded[0] == 7);       // "example" length
    assert(encoded[8] == 3);       // "com" length
    assert(encoded[12] == 0);      // root label

    // Subdomain
    auto sub = encodeDNSName("www.example.com");
    assert(sub.size() == 17);
    assert(sub[0] == 3);  // "www" length

    // Build full DNS query packet
    auto packet = buildDNSQuery("8.8.8.8.origin.asn.cymru.com", DNSType::TXT, 0xABCD);
    assert(packet.size() > 12);  // At least header
    assert(packet[0] == 0xAB && packet[1] == 0xCD);  // ID
    assert(packet[2] == 0x01);  // RD=1
    assert(packet[4] == 0x00 && packet[5] == 0x01);  // QDCOUNT=1

    std::cout << "  DNS query building ✓ (packet=" << packet.size() << " bytes)\n";
}

// ============================================================================
// Test Traceroute Parsing
// ============================================================================

void testTracerouteParsing() {
    std::string output =
        "traceroute to 8.8.8.8, 30 hops max, 60 byte packets\n"
        " 1  gateway (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms\n"
        " 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.890 ms  6.012 ms\n"
        " 3  * * *\n"
        " 4  72.14.236.68 (72.14.236.68)  8.234 ms  8.456 ms  8.678 ms\n"
        " 5  dns.google (8.8.8.8)  10.123 ms  10.456 ms  10.789 ms\n";

    auto hops = parseTraceroute(output);
    assert(hops.size() == 5);

    // Hop 1: gateway
    assert(hops[0].hop_number == 1);
    assert(hops[0].hostname == "gateway");
    assert(hops[0].ip == "192.168.1.1");
    assert(!hops[0].timeout);

    // Hop 3: timeout
    assert(hops[2].hop_number == 3);
    assert(hops[2].timeout);

    // Hop 5: destination
    assert(hops[4].hop_number == 5);
    assert(hops[4].ip == "8.8.8.8");

    // Convert to NetRecords (should skip timeouts)
    auto records = tracerouteToRecords(hops);
    assert(records.size() == 4);  // 5 hops minus 1 timeout

    std::cout << "  Traceroute parsing ✓ (" << hops.size() << " hops, "
              << records.size() << " records)\n";
}

// ============================================================================
// Test Known ASN Lookup
// ============================================================================

void testKnownASN() {
    // Google DNS: AS15169
    auto* google = lookupKnownASN(15169);
    assert(google != nullptr);
    assert(google->asn == 15169);
    assert(std::string(google->org).find("Google") != std::string::npos);
    assert(std::string(google->country) == "US");

    // Cloudflare: AS13335
    auto* cf = lookupKnownASN(13335);
    assert(cf != nullptr);
    assert(cf->asn == 13335);
    assert(std::string(cf->org).find("Cloudflare") != std::string::npos);

    // AWS: AS16509
    auto* aws = lookupKnownASN(16509);
    assert(aws != nullptr);

    // Unknown ASN
    auto* unknown = lookupKnownASN(99999);
    assert(unknown == nullptr);

    // Test enrichment
    NetRecord rec{};
    rec.asn = 15169;
    enrichWithASN(rec);
    assert(std::string(rec.asn_org).find("Google") != std::string::npos);
    assert(std::string(rec.country) == "US");

    std::cout << "  Known ASN lookup ✓ (15169=Google, 13335=Cloudflare)\n";
}

// ============================================================================
// Test IPv4 Parsing
// ============================================================================

void testIPv4Parsing() {
    IPv4Addr addr;
    assert(parseIPv4("8.8.8.8", addr));
    assert(addr.octets[0] == 8 && addr.octets[3] == 8);

    assert(parseIPv4("192.168.1.100", addr));
    assert(addr.octets[0] == 192 && addr.octets[3] == 100);

    assert(parseIPv4("255.255.255.255", addr));
    assert(addr.octets[0] == 255);

    // Invalid
    assert(!parseIPv4("256.1.1.1", addr));
    assert(!parseIPv4("not-an-ip", addr));
    assert(!parseIPv4("", addr));

    std::cout << "  IPv4 parsing ✓\n";
}

int main() {
    std::cout << "=== netrecon-sdn-plugin tests ===\n";
    testSerialization();
    testFilters();
    testIPv4Parsing();
    testCymruASN();
    testDNSQuery();
    testTracerouteParsing();
    testKnownASN();
    std::cout << "All NETRECON tests passed.\n";
    return 0;
}
