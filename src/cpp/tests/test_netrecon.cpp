#include "netrecon/types.h"
#include <iostream>
#include <cassert>
#include <cstring>
#include <cmath>
using namespace netrecon;
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
int main() { std::cout << "=== netrecon tests ===\n"; testSerialization(); testFilters();
    std::cout << "All NETRECON tests passed.\n"; return 0; }
