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

    std::expected<uint32_t, std::string> resolve(const std::string& name) {
        return 0;  // stub
    }
};

}  // namespace dns

#endif
