#ifndef ASTROLUNE_DNS_LUNE_RESOLVER_HPP
#define ASTROLUNE_DNS_LUNE_RESOLVER_HPP

#include <cstdint>
#include <expected>
#include <string>
#include <unordered_map>
#include <vector>

namespace dns {

enum class RecordType : uint16_t {
    A     = 1,
    AAAA  = 28,
    CNAME = 5,
    TXT   = 16,
    NS    = 2,
};

struct DnsRecord {
    std::string name;
    std::vector<uint8_t> rdata;
    RecordType type = RecordType::A;
    uint32_t ttl = 0;
};

struct LuneResolverError {
    std::string message;
    static LuneResolverError make(std::string msg) {
        return LuneResolverError{std::move(msg)};
    }
};

class LuneResolver {
public:
    LuneResolver() = default;
    ~LuneResolver() = default;

    void set_port(uint16_t) {}
    void set_default_upstream(const std::string&) {}

    std::expected<void, LuneResolverError> start() { return {}; }
    void stop() {}

    std::expected<std::vector<DnsRecord>, LuneResolverError>
    resolve(std::string_view name, RecordType type = RecordType::A) {
        return std::vector<DnsRecord>{};
    }

    const std::unordered_map<std::string, DnsRecord>& cache() const {
        static const std::unordered_map<std::string, DnsRecord> empty;
        return empty;
    }
};

}  // namespace dns

#endif
