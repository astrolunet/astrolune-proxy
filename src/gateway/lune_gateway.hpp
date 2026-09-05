/*
 * astrolune/tools/ecosystem/gateway/lune_gateway.hpp
 *
 * HTTP gateway for static .lune websites.  Listens on a configurable port,
 * accepts HTTP requests whose Host header matches *.lune, looks up the domain
 * in the name indexer to obtain a content hash, and serves the corresponding
 * files from a content-addressed store.
 *
 * Thread-per-connection model.  No exceptions across ABI boundaries; errors
 * are returned via std::expected.
 */

#ifndef ASTROLUNE_GATEWAY_LUNE_GATEWAY_HPP
#define ASTROLUNE_GATEWAY_LUNE_GATEWAY_HPP

#include "astrolune/base.h"
#include "astrolune/hash.h"
#include "tools/ecosystem/indexer/name_indexer.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::gateway {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint16_t kDefaultGatewayPort = 8080;
constexpr size_t   kMaxRequestBytes    = 8192;
constexpr size_t   kMaxHeaderBytes     = 8192;

// ---------------------------------------------------------------------------
// HTTP methods
// ---------------------------------------------------------------------------

enum class HttpMethod : uint8_t {
    Get,
    Head,
    Options,
    Unknown,
};

// ---------------------------------------------------------------------------
// Gateway error codes
// ---------------------------------------------------------------------------

enum class GatewayErrorCode {
    SocketCreateFailed,
    SocketBindFailed,
    SocketListenFailed,
    SocketAcceptFailed,
    SocketSendFailed,
    SocketRecvFailed,
    HttpMalformedRequest,
    HttpHeaderTooLarge,
    HttpBodyTooLarge,
    HostHeaderMissing,
    DomainNotFound,
    DomainExpired,
    ContentHashMissing,
    ContentStoreError,
    ContentTypeUnknown,
    AlreadyRunning,
    NotRunning,
    InternalError,
};

struct GatewayError {
    GatewayErrorCode code = GatewayErrorCode::InternalError;
    std::string message;

    static GatewayError make(GatewayErrorCode c, std::string msg) {
        return GatewayError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// GatewayConfig — immutable after construction
// ---------------------------------------------------------------------------

struct GatewayConfig {
    uint16_t listen_port = kDefaultGatewayPort;

    // Bind address.  "0.0.0.0" for all interfaces, "127.0.0.1" for loopback.
    std::string bind_address = "127.0.0.1";

    // Enable CORS headers for development.
    bool cors_enabled = true;
    std::string cors_origin = "*";

    // SPA fallback: serve index.html for paths that don't match a file.
    bool spa_fallback = true;

    // Path to CA certificate bundle for future HTTPS support.
    std::string ca_cert_path;

    // Maximum concurrent connections (0 = unlimited).
    size_t max_connections = 0;

    // Request read timeout in milliseconds.
    uint32_t request_timeout_ms = 10000;

    // Root directory for content-addressed store on disk.
    std::filesystem::path content_store_root;
};

// ---------------------------------------------------------------------------
// ContentStore — interface for accessing content by hash
// ---------------------------------------------------------------------------

// A blob retrieved from the content-addressed store.
struct ContentBlob {
    al_hash256 content_hash{};
    std::vector<uint8_t> data;
};

// Abstract interface.  Implementations may back this with an on-disk store,
// an in-memory cache, or a network fetch.
class ContentStore {
public:
    virtual ~ContentStore() = default;

    // Retrieve content by its SHA-256 hash.  Returns an error if the content
    // is not available.
    virtual std::expected<ContentBlob, GatewayError> get(
        const al_hash256& content_hash) = 0;

    // Check whether content with the given hash exists.
    virtual bool has(const al_hash256& content_hash) const = 0;
};

// ---------------------------------------------------------------------------
// DiskContentStore — on-disk content-addressed store
// ---------------------------------------------------------------------------

// Layout: <root>/<hex[0:2]>/<hex[2:4]>/<hex[4]>.<rest>
// e.g.  /store/ab/cd/ef0123...ff
class DiskContentStore : public ContentStore {
public:
    explicit DiskContentStore(std::filesystem::path root);
    ~DiskContentStore() override;

    DiskContentStore(const DiskContentStore&) = delete;
    DiskContentStore& operator=(const DiskContentStore&) = delete;
    DiskContentStore(DiskContentStore&&) noexcept;
    DiskContentStore& operator=(DiskContentStore&&) noexcept;

    std::expected<ContentBlob, GatewayError> get(
        const al_hash256& content_hash) override;

    bool has(const al_hash256& content_hash) const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// HttpParsedRequest — a parsed HTTP/1.1 request
// ---------------------------------------------------------------------------

struct HttpParsedRequest {
    HttpMethod method = HttpMethod::Unknown;
    std::string path;
    std::string host;
    std::string raw_headers;
    bool keep_alive = false;
};

// ---------------------------------------------------------------------------
// LuneGateway — the main gateway server
// ---------------------------------------------------------------------------

class LuneGateway {
public:
    LuneGateway();
    explicit LuneGateway(GatewayConfig config);
    ~LuneGateway();

    LuneGateway(const LuneGateway&) = delete;
    LuneGateway& operator=(const LuneGateway&) = delete;
    LuneGateway(LuneGateway&&) noexcept;
    LuneGateway& operator=(LuneGateway&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Start listening.  Spawns the accept thread.
    std::expected<void, GatewayError> start();

    // Stop the gateway and close all active connections.
    void stop();

    // True when the accept loop is running.
    bool is_running() const;

    // --- Configuration (must be set before start()) -----------------------

    void set_config(GatewayConfig config);
    const GatewayConfig& config() const;

    // --- Dependencies (must be set before start()) ------------------------

    // Set the name indexer used for domain lookups.  Ownership is shared.
    void set_indexer(std::shared_ptr<indexer::NameIndexer> indexer);

    // Set the content store used for file retrieval.  Ownership is shared.
    void set_content_store(std::shared_ptr<ContentStore> store);

    // --- Request handling (public for unit tests) -------------------------

    // Parse a raw HTTP request into structured fields.
    static std::expected<HttpParsedRequest, GatewayError> parse_request(
        const uint8_t* data, size_t len);

    // Extract the bare domain name from a Host header value.
    // "alice.lune" -> "alice", "www.bob.lune" -> "www.bob"
    static std::expected<std::string, GatewayError> extract_domain(
        std::string_view host);

    // Map a file extension to a MIME content-type string.
    static std::string_view content_type_for(std::string_view path);

    // Build an HTTP response header block.
    static std::string build_response(
        int status_code,
        std::string_view status_text,
        std::string_view content_type,
        size_t content_length,
        bool keep_alive,
        const GatewayConfig& cfg);

    // --- Connection tracking -----------------------------------------------

    size_t connection_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace astrolune::gateway

#endif  // ASTROLUNE_GATEWAY_LUNE_GATEWAY_HPP
