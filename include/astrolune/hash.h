#ifndef ASTROLUNE_HASH_H
#define ASTROLUNE_HASH_H

#include "base.h"
#include <openssl/sha.h>
#include <string>
#include <cstdio>

#define AL_TAG_CONTRACT_DATA 1u
#define AL_TAG_EVENT 2u
#define AL_TAG_MERKLE_NODE 3u

inline void al_sha256(const void* data, size_t len, al_hash256* out) {
    SHA256(static_cast<const unsigned char*>(data), len, out->data);
    memcpy(out->bytes, out->data, 32);
}

inline al_hash256 al_sha256(const void* data, size_t len) {
    al_hash256 out{};
    al_sha256(data, len, &out);
    return out;
}

inline std::string al_hash256_hex(const al_hash256& h) {
    char buf[65]{};
    for (int i = 0; i < 32; ++i)
        snprintf(buf + i * 2, 3, "%02x", h.data[i]);
    return std::string(buf);
}

inline bool al_hash_eq(const al_hash256* a, const al_hash256* b) {
    return memcmp(a->data, b->data, 32) == 0;
}

inline al_hash256 al_hash_zero() { return {}; }

inline void al_hash_tagged(al_u32, const void*, size_t, al_hash256* out) {
    *out = {};
}

inline void al_hash_tagged_pair(al_u32, const al_hash256*, const al_hash256*, al_hash256* out) {
    *out = {};
}

#endif
