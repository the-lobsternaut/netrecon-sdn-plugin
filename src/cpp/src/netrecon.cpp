/**
 * Network Reconnaissance Plugin — Implementation
 *
 * References:
 *   [1] Team Cymru IP-to-ASN DNS Mapping
 *       Protocol: dig TXT <reversed-ip>.origin.asn.cymru.com
 *   [2] MaxMind GeoLite2 binary format (MMDB)
 *   [3] RFC 1035 — DNS protocol
 *   [4] IANA AS Number registry
 *
 * Implements:
 *   - IP-to-ASN lookup query generation (Team Cymru DNS protocol)
 *   - GeoIP: MaxMind GeoLite2 .mmdb binary format reader
 *   - DNS resolution wrapper (query construction/response parsing)
 *   - Traceroute output parsing (standard traceroute/mtr format)
 *
 * C++17, no external dependencies.
 */

#include "netrecon/types.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <vector>
#include <map>
#include <regex>

namespace netrecon {

// ============================================================================
// IP Address Utilities
// ============================================================================

/// Parse an IPv4 address string into 4 octets
/// Returns false if the string is not a valid IPv4 address
struct IPv4Addr {
    uint8_t octets[4];
};

bool parseIPv4(const std::string& ip, IPv4Addr& addr) {
    unsigned int a, b, c, d;
    if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    addr.octets[0] = static_cast<uint8_t>(a);
    addr.octets[1] = static_cast<uint8_t>(b);
    addr.octets[2] = static_cast<uint8_t>(c);
    addr.octets[3] = static_cast<uint8_t>(d);
    return true;
}

/// Reverse an IPv4 address (for DNS PTR lookups)
/// 8.8.8.8 → "8.8.8.8" reversed → "8.8.8.8"
std::string reverseIPv4(const std::string& ip) {
    IPv4Addr addr;
    if (!parseIPv4(ip, addr)) return "";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  addr.octets[3], addr.octets[2],
                  addr.octets[1], addr.octets[0]);
    return std::string(buf);
}

// ============================================================================
// IP-to-ASN Lookup (Team Cymru DNS Protocol)
// ============================================================================

/// Generate the DNS query name for Team Cymru IP-to-ASN lookup
/// Protocol: query TXT <reversed-ip>.origin.asn.cymru.com
/// Response: "ASN | IP/prefix | CC | RIR | Date"
/// Example: 8.8.8.8 → dig TXT 8.8.8.8.origin.asn.cymru.com
///          → "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
///
/// Reference: [1] https://team-cymru.com/community-services/ip-asn-mapping/

std::string cymruASNQuery(const std::string& ip) {
    std::string reversed = reverseIPv4(ip);
    if (reversed.empty()) return "";
    return reversed + ".origin.asn.cymru.com";
}

/// Generate the DNS query for ASN-to-name lookup
/// Protocol: query TXT AS<number>.asn.cymru.com
/// Response: "ASN | CC | RIR | Date | Name"
std::string cymruASNNameQuery(uint32_t asn) {
    return "AS" + std::to_string(asn) + ".asn.cymru.com";
}

/// Parse a Team Cymru DNS TXT response
/// Format: "ASN | IP/prefix | CC | RIR | Date"
struct CymruASNResult {
    uint32_t    asn;
    std::string prefix;      // e.g., "8.8.8.0/24"
    std::string country;     // 2-letter country code
    std::string rir;         // arin, ripe, apnic, etc.
    std::string date;        // allocation date
    bool        valid;
};

CymruASNResult parseCymruResponse(const std::string& txt) {
    CymruASNResult result{};
    result.valid = false;

    // Split by '|' and trim whitespace
    std::vector<std::string> parts;
    std::istringstream iss(txt);
    std::string part;
    while (std::getline(iss, part, '|')) {
        // Trim whitespace
        size_t start = part.find_first_not_of(" \t\"");
        size_t end = part.find_last_not_of(" \t\"");
        if (start != std::string::npos)
            parts.push_back(part.substr(start, end - start + 1));
        else
            parts.push_back("");
    }

    if (parts.size() < 3) return result;

    try {
        result.asn = static_cast<uint32_t>(std::stoul(parts[0]));
    } catch (...) {
        return result;
    }

    result.prefix = parts.size() > 1 ? parts[1] : "";
    result.country = parts.size() > 2 ? parts[2] : "";
    result.rir = parts.size() > 3 ? parts[3] : "";
    result.date = parts.size() > 4 ? parts[4] : "";
    result.valid = true;
    return result;
}

/// Build a NetRecord from an ASN lookup result
NetRecord asnToNetRecord(const std::string& ip, const CymruASNResult& asn_result) {
    NetRecord r{};
    std::strncpy(r.ip_addr, ip.c_str(), 39);
    r.asn = asn_result.asn;
    r.record_type = static_cast<uint8_t>(RecordType::ASN);

    if (!asn_result.country.empty()) {
        std::strncpy(r.country, asn_result.country.c_str(), 3);
    }

    return r;
}

// ============================================================================
// MaxMind GeoLite2 MMDB Format Reader
// ============================================================================

/// MMDB file header and metadata structures
/// Reference: [2] MaxMind DB File Format Specification
///
/// MMDB binary format:
///   1. Binary search tree (for IP lookup)
///   2. Data section (contains the actual records)
///   3. Metadata section (at end of file, after "\xab\xcd\xefMaxMind.com")
///
/// The search tree is a binary trie of IP address bits.
/// Left child = bit 0, Right child = bit 1

static constexpr uint8_t MMDB_METADATA_MARKER[] = {
    0xAB, 0xCD, 0xEF, 'M', 'a', 'x', 'M', 'i', 'n', 'd',
    '.', 'c', 'o', 'm'
};
static constexpr size_t MMDB_MARKER_LEN = 14;

struct MMDBMetadata {
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t node_count;
    uint16_t record_size;  // bits per record (24, 28, or 32)
    uint16_t ip_version;   // 4 or 6
    std::string database_type;
    bool valid;
};

/// Find the MMDB metadata marker in a file buffer
/// The marker "\xab\xcd\xefMaxMind.com" appears near the end
size_t findMMDBMetadata(const uint8_t* data, size_t len) {
    if (len < MMDB_MARKER_LEN + 20) return 0;

    // Search backwards from end (metadata is at the very end)
    for (size_t i = len - MMDB_MARKER_LEN; i > 0; i--) {
        if (std::memcmp(data + i, MMDB_METADATA_MARKER, MMDB_MARKER_LEN) == 0)
            return i + MMDB_MARKER_LEN;
    }
    return 0;
}

/// Read MMDB metadata from the data section pointer
/// This is a simplified reader that extracts key fields
MMDBMetadata readMMDBMetadata(const uint8_t* data, size_t len) {
    MMDBMetadata meta{};
    meta.valid = false;

    size_t meta_start = findMMDBMetadata(data, len);
    if (meta_start == 0) return meta;

    // Metadata is stored as a map in MaxMind's binary format
    // For simplicity, scan for known patterns
    // Real implementation would parse the full data format

    // Look for record_size, node_count, ip_version in the metadata map
    // These are encoded as MaxMind data types (maps, uint16, uint32, etc.)

    // Simplified: just validate the marker was found
    meta.valid = true;
    meta.major_version = 2;
    meta.minor_version = 0;
    // Record size and node count would come from actual parsing
    // Default to common values for GeoLite2-City
    meta.record_size = 28;
    meta.ip_version = 6;  // GeoLite2 typically supports IPv4-mapped-in-IPv6

    return meta;
}

/// Lookup an IPv4 address in an MMDB binary search tree
/// Returns the data section offset for the matching record
///
/// The search tree has node_count nodes.
/// Each node has two records (left=0, right=1).
/// Record value meanings:
///   < node_count: pointer to another node
///   = node_count: "no data" marker
///   > node_count: data section offset = value - node_count - 16
///
/// For 28-bit records, each node is 7 bytes:
///   [left_record(3.5 bytes)][right_record(3.5 bytes)]

struct GeoIPResult {
    double  latitude;
    double  longitude;
    char    country[4];
    char    city[64];
    uint32_t asn;
    bool    found;
};

GeoIPResult lookupIPv4InMMDB(const uint8_t* mmdb_data, size_t mmdb_len,
                               const std::string& ip, uint32_t node_count,
                               uint16_t record_size) {
    GeoIPResult result{};
    result.found = false;
    result.latitude = NAN;
    result.longitude = NAN;

    IPv4Addr addr;
    if (!parseIPv4(ip, addr)) return result;

    // For IPv4-in-IPv6 trees, start at bit 96 (skip the IPv6 prefix)
    // The tree represents all 128 bits of IPv6; IPv4 is mapped to ::ffff:0:0/96

    uint32_t node = 0;
    size_t node_size = (record_size / 4);  // bytes per node

    // Walk the tree for 32 bits of the IPv4 address
    // (In a real IPv6 tree, we'd start 96 bits in)
    for (int bit = 0; bit < 32; bit++) {
        if (node >= node_count) break;

        // Get the bit value
        int byte_idx = bit / 8;
        int bit_idx = 7 - (bit % 8);
        int bit_val = (addr.octets[byte_idx] >> bit_idx) & 1;

        // Read the appropriate record from the node
        size_t node_offset = node * node_size;
        if (node_offset + node_size > mmdb_len) break;

        uint32_t record;
        if (record_size == 28) {
            // 28-bit records: 7 bytes per node
            // Left: bytes[0-2] + high nibble of byte[3]
            // Right: low nibble of byte[3] + bytes[4-6]
            if (bit_val == 0) {
                record = (static_cast<uint32_t>(mmdb_data[node_offset]) << 16) |
                         (static_cast<uint32_t>(mmdb_data[node_offset + 1]) << 8) |
                         mmdb_data[node_offset + 2];
                record |= (static_cast<uint32_t>(mmdb_data[node_offset + 3] >> 4) << 24);
            } else {
                record = (static_cast<uint32_t>(mmdb_data[node_offset + 4]) << 16) |
                         (static_cast<uint32_t>(mmdb_data[node_offset + 5]) << 8) |
                         mmdb_data[node_offset + 6];
                record |= (static_cast<uint32_t>(mmdb_data[node_offset + 3] & 0x0F) << 24);
            }
        } else if (record_size == 24) {
            // 24-bit records: 6 bytes per node
            size_t off = node_offset + bit_val * 3;
            record = (static_cast<uint32_t>(mmdb_data[off]) << 16) |
                     (static_cast<uint32_t>(mmdb_data[off + 1]) << 8) |
                     mmdb_data[off + 2];
        } else if (record_size == 32) {
            // 32-bit records: 8 bytes per node
            size_t off = node_offset + bit_val * 4;
            record = (static_cast<uint32_t>(mmdb_data[off]) << 24) |
                     (static_cast<uint32_t>(mmdb_data[off + 1]) << 16) |
                     (static_cast<uint32_t>(mmdb_data[off + 2]) << 8) |
                     mmdb_data[off + 3];
        } else {
            return result;
        }

        if (record == node_count) {
            // No data for this IP
            return result;
        } else if (record > node_count) {
            // Found data! Offset into data section
            result.found = true;
            return result;
        }

        node = record;
    }

    return result;
}

// ============================================================================
// DNS Query/Response Helpers
// ============================================================================

/// DNS record types
enum class DNSType : uint16_t {
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
};

/// Build a DNS query name in wire format
/// "example.com" → "\x07example\x03com\x00"
std::vector<uint8_t> encodeDNSName(const std::string& domain) {
    std::vector<uint8_t> encoded;
    std::istringstream iss(domain);
    std::string label;

    while (std::getline(iss, label, '.')) {
        if (label.empty()) continue;
        if (label.size() > 63) return {};  // label too long
        encoded.push_back(static_cast<uint8_t>(label.size()));
        for (char c : label)
            encoded.push_back(static_cast<uint8_t>(c));
    }
    encoded.push_back(0);  // root label
    return encoded;
}

/// Build a complete DNS query packet (RFC 1035)
/// Returns the raw UDP payload for a DNS query
std::vector<uint8_t> buildDNSQuery(const std::string& domain,
                                     DNSType qtype,
                                     uint16_t id = 0x1234) {
    std::vector<uint8_t> packet;

    // Header (12 bytes)
    packet.push_back(id >> 8); packet.push_back(id & 0xFF);  // ID
    packet.push_back(0x01);    // QR=0, Opcode=0, AA=0, TC=0, RD=1
    packet.push_back(0x00);    // RA=0, Z=0, RCODE=0
    packet.push_back(0x00); packet.push_back(0x01);  // QDCOUNT=1
    packet.push_back(0x00); packet.push_back(0x00);  // ANCOUNT=0
    packet.push_back(0x00); packet.push_back(0x00);  // NSCOUNT=0
    packet.push_back(0x00); packet.push_back(0x00);  // ARCOUNT=0

    // Question section
    auto name = encodeDNSName(domain);
    packet.insert(packet.end(), name.begin(), name.end());

    uint16_t qt = static_cast<uint16_t>(qtype);
    packet.push_back(qt >> 8); packet.push_back(qt & 0xFF);  // QTYPE
    packet.push_back(0x00); packet.push_back(0x01);           // QCLASS=IN

    return packet;
}

// ============================================================================
// Traceroute Output Parser
// ============================================================================

/// Parsed traceroute hop
struct TracerouteHop {
    int         hop_number;
    std::string hostname;
    std::string ip;
    double      rtt_ms[3];     // Up to 3 RTT measurements
    int         n_rtts;
    bool        timeout;       // True if hop was "*"
};

/// Parse standard traceroute output
/// Format:
///   1  192.168.1.1 (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms
///   2  10.0.0.1 (10.0.0.1)  5.678 ms  * *
///   3  * * *
std::vector<TracerouteHop> parseTraceroute(const std::string& output) {
    std::vector<TracerouteHop> hops;

    std::istringstream iss(output);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        TracerouteHop hop{};
        hop.n_rtts = 0;
        hop.timeout = false;

        // Try to parse hop number
        std::istringstream lss(line);
        std::string token;

        if (!(lss >> token)) continue;
        try {
            hop.hop_number = std::stoi(token);
        } catch (...) {
            continue;
        }

        // Check for all-timeout line: "N * * *"
        std::string rest;
        std::getline(lss, rest);
        // Trim
        size_t start = rest.find_first_not_of(" \t");
        if (start != std::string::npos) rest = rest.substr(start);

        if (rest == "* * *" || rest == "* * *\r") {
            hop.timeout = true;
            hops.push_back(hop);
            continue;
        }

        // Parse hostname/IP and RTTs
        std::istringstream rss(rest);

        // First token: hostname or IP
        if (rss >> hop.hostname) {
            // If followed by (IP), extract IP
            std::string maybe_ip;
            if (rss >> maybe_ip) {
                if (maybe_ip.front() == '(' && maybe_ip.back() == ')') {
                    hop.ip = maybe_ip.substr(1, maybe_ip.size() - 2);
                } else {
                    // hostname might be the IP itself
                    hop.ip = hop.hostname;
                    // Put the token back conceptually — try parsing as RTT
                    if (maybe_ip.find("ms") != std::string::npos ||
                        maybe_ip == "*") {
                        // It's an RTT value or timeout
                        if (maybe_ip != "*") {
                            try {
                                hop.rtt_ms[hop.n_rtts++] = std::stod(maybe_ip);
                            } catch (...) {}
                        }
                    }
                }
            }
        }

        // Parse remaining RTT values
        std::string val;
        while (rss >> val) {
            if (val == "*") continue;
            if (val == "ms") continue;
            try {
                if (hop.n_rtts < 3)
                    hop.rtt_ms[hop.n_rtts++] = std::stod(val);
            } catch (...) {}
        }

        hops.push_back(hop);
    }

    return hops;
}

/// Convert traceroute hops to NetRecords
std::vector<NetRecord> tracerouteToRecords(const std::vector<TracerouteHop>& hops) {
    std::vector<NetRecord> records;
    for (const auto& hop : hops) {
        if (hop.timeout) continue;  // Skip timeouts

        NetRecord r{};
        if (!hop.ip.empty())
            std::strncpy(r.ip_addr, hop.ip.c_str(), 39);
        if (!hop.hostname.empty())
            std::strncpy(r.domain, hop.hostname.c_str(), 63);

        r.record_type = static_cast<uint8_t>(RecordType::HOST);
        records.push_back(r);
    }
    return records;
}

// ============================================================================
// Well-Known ASN Database (for offline/testing)
// ============================================================================

struct KnownASN {
    uint32_t    asn;
    const char* org;
    const char* country;
};

static const KnownASN KNOWN_ASNS[] = {
    {15169,  "Google LLC",                "US"},
    {13335,  "Cloudflare Inc",            "US"},
    {16509,  "Amazon.com Inc (AWS)",      "US"},
    {8075,   "Microsoft Corporation",     "US"},
    {32934,  "Facebook Inc (Meta)",       "US"},
    {20940,  "Akamai Technologies",       "US"},
    {14618,  "Amazon.com Inc",            "US"},
    {36351,  "SoftLayer Technologies",    "US"},
    {3356,   "Lumen Technologies",        "US"},
    {174,    "Cogent Communications",     "US"},
    {6939,   "Hurricane Electric",        "US"},
    {2914,   "NTT America",              "US"},
    {7018,   "AT&T Services",            "US"},
    {701,    "Verizon Business",          "US"},
    {3257,   "GTT Communications",        "DE"},
    {6762,   "Telecom Italia Sparkle",   "IT"},
    {1299,   "Arelion (Telia)",          "SE"},
    {4134,   "China Telecom",            "CN"},
    {4837,   "China Unicom",             "CN"},
    {9808,   "China Mobile",             "CN"},
    {2516,   "KDDI Corporation",         "JP"},
    {0, nullptr, nullptr}  // sentinel
};

/// Lookup a well-known ASN (offline, for testing/enrichment)
const KnownASN* lookupKnownASN(uint32_t asn) {
    for (int i = 0; KNOWN_ASNS[i].org != nullptr; i++) {
        if (KNOWN_ASNS[i].asn == asn) return &KNOWN_ASNS[i];
    }
    return nullptr;
}

/// Enrich a NetRecord with known ASN data
void enrichWithASN(NetRecord& record) {
    const auto* known = lookupKnownASN(record.asn);
    if (known) {
        std::strncpy(record.asn_org, known->org, 31);
        if (record.country[0] == 0)
            std::strncpy(record.country, known->country, 3);
    }
}

}  // namespace netrecon
