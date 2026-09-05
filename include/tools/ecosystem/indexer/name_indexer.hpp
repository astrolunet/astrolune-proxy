#ifndef ASTROLUNE_INDEXER_NAME_INDEXER_HPP
#define ASTROLUNE_INDEXER_NAME_INDEXER_HPP

#include "astrolune/hash.h"
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace astrolune::indexer {

struct DomainInfo {
    std::string name;
    al_hash256 content_hash;
    uint32_t ttl = 3600;
    bool active = true;
};

struct IndexerError {
    std::string message;
};

class NameIndexer {
public:
    NameIndexer() = default;
    ~NameIndexer() = default;

    std::expected<DomainInfo, IndexerError> lookup(const al_hash256& hash) {
        return std::unexpected(IndexerError{"stub"});
    }

    std::expected<DomainInfo, IndexerError> lookup(const std::string& name) {
        return std::unexpected(IndexerError{"stub"});
    }

    std::expected<void, IndexerError> index(const std::string& name, const al_hash256& hash) {
        return {};
    }
};

}  // namespace astrolune::indexer

#endif
