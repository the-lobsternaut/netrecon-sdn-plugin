#ifndef NETRECON_TYPES_H
#define NETRECON_TYPES_H

/**
 * Network Reconnaissance (NETRECON) Plugin Types
 * =================================================
 *
 * Passive network intelligence — DNS, WHOIS, certificate transparency,
 * subdomain enumeration, IP geolocation, ASN mapping.
 *
 * Data sources:
 *   1. DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
 *   2. WHOIS/RDAP registrar data
 *   3. Certificate Transparency logs (crt.sh)
 *   4. Shodan / Censys (host discovery)
 *   5. BGP/ASN routing data (RIPE, ARIN)
 *
 * Output: $NET FlatBuffer-aligned binary records
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>

namespace netrecon {

static constexpr char NET_FILE_ID[4] = {'$', 'N', 'E', 'T'};
static constexpr uint32_t NET_VERSION = 1;

enum class RecordType : uint8_t {
    DNS_A     = 0,
    DNS_AAAA  = 1,
    DNS_MX    = 2,
    DNS_NS    = 3,
    DNS_TXT   = 4,
    DNS_CNAME = 5,
    WHOIS     = 10,
    CERT_CT   = 20,  // Certificate Transparency
    HOST      = 30,  // Shodan/Censys host
    ASN       = 40,  // BGP/ASN mapping
    SUBDOMAIN = 50,  // Enumerated subdomain
};

enum class RiskLevel : uint8_t {
    UNKNOWN   = 0,
    LOW       = 1,
    MEDIUM    = 2,
    HIGH      = 3,
    CRITICAL  = 4,
};

enum class InfraFlag : uint8_t {
    NONE          = 0,
    CDN           = 1,   // Behind CDN
    CLOUD         = 2,   // Cloud-hosted
    SELF_HOSTED   = 4,   // Self-hosted infrastructure
    GOV           = 8,   // Government domain
    MIL           = 16,  // Military domain
    EDU           = 32,  // Educational
    EXPIRED_CERT  = 64,  // SSL certificate expired
    OPEN_PORTS    = 128, // Unusual open ports
};

#pragma pack(push, 1)

struct NETHeader {
    char     magic[4];
    uint32_t version;
    uint32_t source;
    uint32_t count;
};
static_assert(sizeof(NETHeader) == 16, "NETHeader must be 16 bytes");

/// Network intelligence record
struct NetRecord {
    // Target
    char     domain[64];       // Domain name
    char     ip_addr[40];      // IPv4 or IPv6 address
    uint16_t port;             // Port number
    uint8_t  record_type;      // RecordType enum
    uint8_t  risk_level;       // RiskLevel enum

    // WHOIS/Registration
    char     registrar[32];    // Domain registrar
    double   created_epoch;    // Domain creation date
    double   expires_epoch;    // Domain expiration date

    // Network
    uint32_t asn;              // Autonomous System Number
    char     asn_org[32];      // ASN organization name

    // Geolocation
    double   lat_deg;          // Server latitude
    double   lon_deg;          // Server longitude
    char     country[4];       // ISO 3166-1

    // Certificate
    char     cert_issuer[32];  // SSL cert issuer
    double   cert_expires;     // Cert expiry epoch

    // Classification
    uint8_t  infra_flags;      // InfraFlag bitfield
    uint8_t  protocol;         // 6=TCP, 17=UDP

    // Metadata
    double   scan_epoch;       // When this record was collected

    uint8_t  reserved[2];
};

#pragma pack(pop)

// ============================================================================
// Serialization
// ============================================================================

inline std::vector<uint8_t> serialize(const std::vector<NetRecord>& records) {
    size_t size = sizeof(NETHeader) + records.size() * sizeof(NetRecord);
    std::vector<uint8_t> buf(size);

    NETHeader hdr;
    std::memcpy(hdr.magic, NET_FILE_ID, 4);
    hdr.version = NET_VERSION;
    hdr.source = 0;
    hdr.count = static_cast<uint32_t>(records.size());
    std::memcpy(buf.data(), &hdr, sizeof(NETHeader));

    if (!records.empty()) {
        std::memcpy(buf.data() + sizeof(NETHeader),
                    records.data(), records.size() * sizeof(NetRecord));
    }
    return buf;
}

inline bool deserialize(const uint8_t* data, size_t len,
                         NETHeader& hdr, std::vector<NetRecord>& records) {
    if (len < sizeof(NETHeader)) return false;
    std::memcpy(&hdr, data, sizeof(NETHeader));
    if (std::memcmp(hdr.magic, NET_FILE_ID, 4) != 0) return false;
    size_t expected = sizeof(NETHeader) + hdr.count * sizeof(NetRecord);
    if (len < expected) return false;
    records.resize(hdr.count);
    if (hdr.count > 0) {
        std::memcpy(records.data(), data + sizeof(NETHeader),
                    hdr.count * sizeof(NetRecord));
    }
    return true;
}

inline std::vector<NetRecord> filterByRisk(
    const std::vector<NetRecord>& records, RiskLevel minLevel) {
    std::vector<NetRecord> out;
    for (const auto& r : records)
        if (r.risk_level >= static_cast<uint8_t>(minLevel)) out.push_back(r);
    return out;
}

inline std::vector<NetRecord> filterByFlag(
    const std::vector<NetRecord>& records, InfraFlag flag) {
    std::vector<NetRecord> out;
    for (const auto& r : records)
        if (r.infra_flags & static_cast<uint8_t>(flag)) out.push_back(r);
    return out;
}

}  // namespace netrecon

#endif
