#ifndef ASTROLUNE_DNS_LUNE_RESOLVER_HPP
#define ASTROLUNE_DNS_LUNE_RESOLVER_HPP

#include <cstdint>
#include <string>
#include <memory>

namespace dns {

class LuneResolver {
public:
    LuneResolver() = default;
    ~LuneResolver() = default;

    void set_port(uint16_t) {}
    void set_default_upstream(const std::string&) {}
    std::expected<void, std::string> start() { return {}; }
    void stop() {}
    std::expected<uint32_t, std::string> resolve(const std::string&) { return 0; }
};

}  // namespace dns

#endif
