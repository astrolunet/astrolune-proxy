#ifndef ASTROLUNE_BASE_H
#define ASTROLUNE_BASE_H

#include <cstdint>
#include <cstring>

using al_u8  = uint8_t;
using al_u16 = uint16_t;
using al_u32 = uint32_t;
using al_u64 = uint64_t;

#define AL_HASH_SIZE 32u

struct al_hash256 {
    al_u8 data[32]{};
    al_u8 bytes[32]{};

    bool operator==(const al_hash256& o) const noexcept {
        return memcmp(data, o.data, 32) == 0;
    }
    bool operator!=(const al_hash256& o) const noexcept {
        return !(*this == o);
    }
};

inline bool al_hash_eq(const al_hash256& a, const al_hash256& b) {
    return memcmp(a.data, b.data, 32) == 0;
}

struct al_address {
    al_u8 data[32]{};
    bool is_zero() const noexcept {
        for (int i = 0; i < 32; ++i) if (data[i]) return false;
        return true;
    }
    bool operator==(const al_address& o) const noexcept {
        return memcmp(data, o.data, 32) == 0;
    }
};

#endif  // ASTROLUNE_BASE_H
