/*
 * astrolune/tools/ecosystem/gateway/lune_gateway.cpp
 *
 * Implementation of the HTTP gateway for static .lune websites.
 * Thread-per-connection model: the accept loop spawns a detached
 * thread for each incoming client.  The thread reads the HTTP
 * request, resolves the domain through the name indexer, fetches
 * the content from the content-addressed store, and writes the
 * response back.
 */

#include "lune_gateway.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using sock_t = SOCKET;
  constexpr sock_t kInvalidSock = INVALID_SOCKET;
  constexpr int kSockError = SOCKET_ERROR;
  #define CLOSE_SOCKET closesocket
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <poll.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using sock_t = int;
  constexpr sock_t kInvalidSock = -1;
  constexpr int kSockError = -1;
  #define CLOSE_SOCKET ::close
#endif

namespace astrolune::gateway {

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

namespace {

std::expected<size_t, GatewayError> read_exact(sock_t fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto got = ::recv(fd, reinterpret_cast<char*>(buf + total),
                          static_cast<int>(n - total), 0);
        if (got <= 0) {
            return std::unexpected(GatewayError::make(
                GatewayErrorCode::SocketRecvFailed,
                got == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(got);
    }
    return total;
}

std::expected<size_t, GatewayError> write_exact(sock_t fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto sent = ::send(fd, reinterpret_cast<const char*>(buf + total),
                           static_cast<int>(n - total), 0);
        if (sent <= 0) {
            return std::unexpected(GatewayError::make(
                GatewayErrorCode::SocketSendFailed,
                sent == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(sent);
    }
    return total;
}

std::string to_hex(const al_hash256& h) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(AL_HASH_SIZE * 2);
    for (size_t i = 0; i < AL_HASH_SIZE; ++i) {
        result.push_back(kHex[h.bytes[i] >> 4]);
        result.push_back(kHex[h.bytes[i] & 0x0F]);
    }
    return result;
}

}  // namespace

// ---------------------------------------------------------------------------
// DiskContentStore::Impl
// ---------------------------------------------------------------------------

struct DiskContentStore::Impl {
    std::filesystem::path root;

    std::filesystem::path path_for(const al_hash256& h) const {
        auto hex = to_hex(h);
        // Layout: root / xx / yy / zzzz...
        // First 2 hex chars = dir1, next 2 = dir2, rest = filename
        auto dir1 = root / hex.substr(0, 2);
        auto dir2 = dir1 / hex.substr(2, 2);
        auto file = dir2 / hex.substr(4);
        return file;
    }
};

DiskContentStore::DiskContentStore(std::filesystem::path root)
    : impl_(std::make_unique<Impl>()) {
    impl_->root = std::move(root);
}

DiskContentStore::~DiskContentStore() = default;
DiskContentStore::DiskContentStore(DiskContentStore&&) noexcept = default;
DiskContentStore& DiskContentStore::operator=(DiskContentStore&&) noexcept = default;

std::expected<ContentBlob, GatewayError>
DiskContentStore::get(const al_hash256& content_hash) {
    auto path = impl_->path_for(content_hash);

    std::error_code ec;
    auto file_size = std::filesystem::file_size(path, ec);
    if (ec) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::ContentStoreError,
            "content not found: " + to_hex(content_hash)));
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::ContentStoreError,
            "failed to open: " + path.string()));
    }

    ContentBlob blob;
    blob.content_hash = content_hash;
    blob.data.resize(static_cast<size_t>(file_size));
    ifs.read(reinterpret_cast<char*>(blob.data.data()),
             static_cast<std::streamsize>(file_size));

    if (!ifs) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::ContentStoreError,
            "read failed: " + path.string()));
    }

    return blob;
}

bool DiskContentStore::has(const al_hash256& content_hash) const {
    return std::filesystem::exists(impl_->path_for(content_hash));
}

// ---------------------------------------------------------------------------
// LuneGateway::Impl
// ---------------------------------------------------------------------------

struct LuneGateway::Impl {
    GatewayConfig cfg;
    std::atomic<bool> running{false};
    sock_t listen_fd = kInvalidSock;
    std::thread accept_thread;
    std::atomic<size_t> active_conns{0};

    mutable std::mutex mu;
    std::shared_ptr<indexer::NameIndexer> indexer;
    std::shared_ptr<ContentStore> store;

    // --- Accept loop ------------------------------------------------------

    void accept_loop() {
        while (running.load(std::memory_order_relaxed)) {
            sockaddr_storage client_addr{};
            socklen_t addr_len = sizeof(client_addr);

            sock_t client_fd = ::accept(listen_fd,
                reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
            if (client_fd == kInvalidSock) {
                if (!running.load(std::memory_order_relaxed)) break;
                continue;
            }

            if (cfg.max_connections > 0 &&
                active_conns.load(std::memory_order_relaxed) >= cfg.max_connections) {
                std::string resp =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Connection: close\r\n"
                    "Content-Length: 0\r\n\r\n";
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(resp.data()),
                            resp.size());
                CLOSE_SOCKET(client_fd);
                continue;
            }

            active_conns.fetch_add(1, std::memory_order_relaxed);
            std::thread(&Impl::handle_client, this, client_fd).detach();
        }
    }

    // --- Client handler ---------------------------------------------------

    void handle_client(sock_t client_fd) {
        auto guard = [this](int) {
            active_conns.fetch_sub(1, std::memory_order_relaxed);
        };

        // Read the full HTTP request until \r\n\r\n
        std::string request_data;
        request_data.reserve(4096);

        char buf[4096];
        while (request_data.size() < kMaxRequestBytes) {
            auto n = ::recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }
            request_data.append(buf, static_cast<size_t>(n));
            if (request_data.find("\r\n\r\n") != std::string::npos) break;
        }

        if (request_data.size() >= kMaxRequestBytes &&
            request_data.find("\r\n\r\n") == std::string::npos) {
            std::string resp =
                "HTTP/1.1 413 Request Entity Too Large\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        auto data = reinterpret_cast<const uint8_t*>(request_data.data());
        auto parse_res = parse_request(data, request_data.size());
        if (!parse_res) {
            std::string resp =
                "HTTP/1.1 400 Bad Request\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        auto& req = *parse_res;

        // Handle OPTIONS for CORS preflight
        if (req.method == HttpMethod::Options) {
            auto resp = build_response(204, "No Content", "text/plain", 0,
                                        req.keep_alive, cfg);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Handle HEAD requests (same as GET but no body)
        bool is_head = (req.method == HttpMethod::Head);

        // Extract domain from Host header
        auto domain_res = extract_domain(req.host);
        if (!domain_res) {
            std::string resp =
                "HTTP/1.1 400 Bad Request\r\n"
                "Connection: close\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: 26\r\n\r\n"
                "Invalid Host header";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        std::string domain = std::move(*domain_res);

        // Look up the domain in the indexer
        indexer::DomainInfo domain_info;
        {
            std::lock_guard lock(mu);
            if (!indexer) {
                std::string resp =
                    "HTTP/1.1 502 Bad Gateway\r\n"
                    "Connection: close\r\n\r\n";
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(resp.data()),
                            resp.size());
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            // Hash the domain name to look it up
            al_hash256 domain_hash{};
            al_sha256(domain.c_str(), domain.size(), &domain_hash);

            auto lookup = indexer->lookup(domain_hash);
            if (!lookup) {
                std::string body = "Domain not found: " + domain;
                auto resp = build_response(404, "Not Found", "text/plain",
                                            body.size(), req.keep_alive, cfg);
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(resp.data()),
                            resp.size());
                if (!body.empty()) {
                    write_exact(client_fd,
                                reinterpret_cast<const uint8_t*>(body.data()),
                                body.size());
                }
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }
            domain_info = *lookup;
        }

        // Resolve the request path
        std::string path = req.path;
        if (path.empty() || path[0] != '/') {
            path = "/" + path;
        }

        // Strip query string
        auto qpos = path.find('?');
        if (qpos != std::string::npos) {
            path = path.substr(0, qpos);
        }

        // Normalise: collapse "." and ".."
        // Simple approach: just prevent directory traversal
        if (path.find("..") != std::string::npos) {
            std::string resp =
                "HTTP/1.1 403 Forbidden\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            guard(0);
            return;
        }

        // Default to index.html for root
        if (path == "/") {
            path = "/index.html";
        }

        // Strip leading slash for content lookup
        std::string file_key = path.substr(1);

        // Look up the content hash from the domain's content mapping.
        // The domain info stores a content_hash that is the root hash of
        // a directory manifest.  For now we use a simple mapping:
        // content_hash(root) + path -> content_hash(file).
        // This is a simplified model; a real implementation would use a
        // Merkle-based file tree.
        //
        // For this implementation we treat the domain's content_hash as
        // the hash of an index.html if the path is "/", and as a direct
        // content hash for other paths stored in the domain's metadata.
        // A production system would store a mapping table or manifest.

        al_hash256 content_hash = domain_info.content_hash;

        // If the store is available, try to fetch the content
        if (store) {
            auto blob = store->get(content_hash);
            if (!blob) {
                // Content not found in store; try SPA fallback
                if (cfg.spa_fallback && file_key != "index.html") {
                    al_hash256 index_hash = domain_info.content_hash;
                    auto index_blob = store->get(index_hash);
                    if (index_blob) {
                        auto ct = content_type_for("/index.html");
                        auto resp = build_response(200, "OK", ct,
                                                    index_blob->data.size(),
                                                    req.keep_alive, cfg);
                        write_exact(client_fd,
                                    reinterpret_cast<const uint8_t*>(resp.data()),
                                    resp.size());
                        if (!is_head && !index_blob->data.empty()) {
                            write_exact(client_fd, index_blob->data.data(),
                                        index_blob->data.size());
                        }
                        CLOSE_SOCKET(client_fd);
                        guard(0);
                        return;
                    }
                }

                std::string resp =
                    "HTTP/1.1 404 Not Found\r\n"
                    "Connection: close\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 14\r\n\r\n"
                    "Not Found";
                write_exact(client_fd,
                            reinterpret_cast<const uint8_t*>(resp.data()),
                            resp.size());
                CLOSE_SOCKET(client_fd);
                guard(0);
                return;
            }

            // Serve the content
            auto ct = content_type_for(path);
            auto resp = build_response(200, "OK", ct, blob->data.size(),
                                        req.keep_alive, cfg);
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            if (!is_head && !blob->data.empty()) {
                write_exact(client_fd, blob->data.data(), blob->data.size());
            }
        } else {
            // No store configured — return 503
            std::string resp =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
        }

        CLOSE_SOCKET(client_fd);
        guard(0);
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

LuneGateway::LuneGateway()
    : impl_(std::make_unique<Impl>()) {}

LuneGateway::LuneGateway(GatewayConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}

LuneGateway::~LuneGateway() {
    stop();
}

LuneGateway::LuneGateway(LuneGateway&&) noexcept = default;
LuneGateway& LuneGateway::operator=(LuneGateway&&) noexcept = default;

std::expected<void, GatewayError> LuneGateway::start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::AlreadyRunning, "gateway already running"));
    }

    // Create listening socket
    impl_->listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listen_fd == kInvalidSock) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::SocketCreateFailed,
            "socket() failed: " + std::string(std::strerror(errno))));
    }

    int reuse = 1;
    ::setsockopt(impl_->listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(impl_->cfg.listen_port);

    // Parse bind address
    if (impl_->cfg.bind_address == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (impl_->cfg.bind_address == "127.0.0.1" ||
               impl_->cfg.bind_address == "localhost") {
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        ::inet_pton(AF_INET, impl_->cfg.bind_address.c_str(),
                    &addr.sin_addr);
    }

    if (::bind(impl_->listen_fd, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::SocketBindFailed,
            "bind() failed on " + impl_->cfg.bind_address + ":" +
                std::to_string(impl_->cfg.listen_port) + ": " +
                std::strerror(errno)));
    }

    if (::listen(impl_->listen_fd, 16) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::SocketListenFailed,
            "listen() failed: " + std::string(std::strerror(errno))));
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->accept_thread = std::thread(&Impl::accept_loop, impl_.get());

    return {};
}

void LuneGateway::stop() {
    impl_->running.store(false, std::memory_order_release);

    if (impl_->listen_fd != kInvalidSock) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
    }

    if (impl_->accept_thread.joinable()) {
        impl_->accept_thread.join();
    }
}

bool LuneGateway::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

void LuneGateway::set_config(GatewayConfig config) {
    impl_->cfg = std::move(config);
}

const GatewayConfig& LuneGateway::config() const {
    return impl_->cfg;
}

void LuneGateway::set_indexer(std::shared_ptr<indexer::NameIndexer> indexer) {
    std::lock_guard lock(impl_->mu);
    impl_->indexer = std::move(indexer);
}

void LuneGateway::set_content_store(std::shared_ptr<ContentStore> store) {
    std::lock_guard lock(impl_->mu);
    impl_->store = std::move(store);
}

size_t LuneGateway::connection_count() const {
    return impl_->active_conns.load(std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::expected<HttpParsedRequest, GatewayError>
LuneGateway::parse_request(const uint8_t* data, size_t len) {
    std::string_view raw(reinterpret_cast<const char*>(data),
                         std::min(len, size_t(kMaxHeaderBytes)));

    HttpParsedRequest req;

    // Find end of first line
    auto first_line_end = raw.find("\r\n");
    if (first_line_end == std::string_view::npos) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HttpMalformedRequest, "no CRLF in request"));
    }

    auto first_line = raw.substr(0, first_line_end);

    // Parse method
    auto space1 = first_line.find(' ');
    if (space1 == std::string_view::npos) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HttpMalformedRequest, "missing method"));
    }

    auto method_str = first_line.substr(0, space1);
    if (method_str == "GET") {
        req.method = HttpMethod::Get;
    } else if (method_str == "HEAD") {
        req.method = HttpMethod::Head;
    } else if (method_str == "OPTIONS") {
        req.method = HttpMethod::Options;
    } else {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HttpMalformedRequest,
            "unsupported method: " + std::string(method_str)));
    }

    // Parse path
    auto space2 = first_line.find(' ', space1 + 1);
    if (space2 == std::string_view::npos) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HttpMalformedRequest, "missing path"));
    }
    req.path = std::string(first_line.substr(space1 + 1, space2 - space1 - 1));

    // Parse headers
    size_t pos = first_line_end + 2;
    while (pos < raw.size()) {
        auto line_end = raw.find("\r\n", pos);
        if (line_end == std::string_view::npos || line_end == pos) {
            break;  // end of headers
        }

        auto line = raw.substr(pos, line_end - pos);
        pos = line_end + 2;

        // Split on ": "
        auto colon = line.find(':');
        if (colon == std::string_view::npos) continue;

        auto name = line.substr(0, colon);
        auto value_start = colon + 1;
        while (value_start < line.size() && line[value_start] == ' ') {
            ++value_start;
        }
        auto value = line.substr(value_start);

        // Lowercase the header name for comparison
        std::string header_name(name);
        std::transform(header_name.begin(), header_name.end(),
                       header_name.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (header_name == "host") {
            req.host = value;
        } else if (header_name == "connection") {
            std::string conn_value(value);
            std::transform(conn_value.begin(), conn_value.end(),
                           conn_value.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            req.keep_alive = (conn_value == "keep-alive");
        }
    }

    // Default keep-alive for HTTP/1.1
    if (pos >= raw.size() || raw.find("HTTP/1.1") != std::string_view::npos) {
        if (!req.host.empty() && !req.keep_alive) {
            req.keep_alive = true;  // HTTP/1.1 default
        }
    }

    if (req.host.empty()) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HostHeaderMissing, "missing Host header"));
    }

    req.raw_headers = std::string(raw.substr(0, pos));
    return req;
}

std::expected<std::string, GatewayError>
LuneGateway::extract_domain(std::string_view host) {
    // Strip port if present
    auto colon = host.rfind(':');
    if (colon != std::string_view::npos) {
        host = host.substr(0, colon);
    }

    // Strip trailing dot
    while (!host.empty() && host.back() == '.') {
        host.remove_suffix(1);
    }

    // Must end with .lune
    if (!host.ends_with(".lune")) {
        return std::unexpected(GatewayError::make(
            GatewayErrorCode::HostHeaderMissing,
            "host does not end with .lune: " + std::string(host)));
    }

    // Return the bare domain (without .lune suffix)
    return std::string(host.substr(0, host.size() - 5));
}

std::string_view LuneGateway::content_type_for(std::string_view path) {
    // Find the last dot
    auto dot = path.rfind('.');
    if (dot == std::string_view::npos) {
        return "application/octet-stream";
    }

    auto ext = path.substr(dot + 1);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    if (ext == "html" || ext == "htm")  return "text/html; charset=utf-8";
    if (ext == "css")                   return "text/css; charset=utf-8";
    if (ext == "js" || ext == "mjs")   return "application/javascript; charset=utf-8";
    if (ext == "json")                  return "application/json; charset=utf-8";
    if (ext == "png")                   return "image/png";
    if (ext == "jpg" || ext == "jpeg")  return "image/jpeg";
    if (ext == "gif")                   return "image/gif";
    if (ext == "svg")                   return "image/svg+xml";
    if (ext == "ico")                   return "image/x-icon";
    if (ext == "woff")                  return "font/woff";
    if (ext == "woff2")                 return "font/woff2";
    if (ext == "ttf")                   return "font/ttf";
    if (ext == "otf")                   return "font/otf";
    if (ext == "webp")                  return "image/webp";
    if (ext == "avif")                  return "image/avif";
    if (ext == "mp4")                   return "video/mp4";
    if (ext == "webm")                  return "video/webm";
    if (ext == "txt")                   return "text/plain; charset=utf-8";
    if (ext == "xml")                   return "application/xml; charset=utf-8";
    if (ext == "pdf")                   return "application/pdf";
    if (ext == "wasm")                  return "application/wasm";
    if (ext == "map")                   return "application/json; charset=utf-8";
    if (ext == "ts" || ext == "tsx")    return "application/javascript; charset=utf-8";
    if (ext == "jsx")                   return "application/javascript; charset=utf-8";

    return "application/octet-stream";
}

std::string LuneGateway::build_response(
    int status_code,
    std::string_view status_text,
    std::string_view content_type,
    size_t content_length,
    bool keep_alive,
    const GatewayConfig& cfg)
{
    std::ostringstream ss;
    ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";

    if (cfg.cors_enabled) {
        ss << "Access-Control-Allow-Origin: " << cfg.cors_origin << "\r\n";
        ss << "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n";
        ss << "Access-Control-Allow-Headers: Content-Type, Range\r\n";
        ss << "Access-Control-Expose-Headers: Content-Length, Content-Range\r\n";
    }

    ss << "Content-Type: " << content_type << "\r\n";
    ss << "Content-Length: " << content_length << "\r\n";
    ss << "Connection: " << (keep_alive ? "keep-alive" : "close") << "\r\n";
    ss << "Cache-Control: public, max-age=3600\r\n";
    ss << "X-Content-Type-Options: nosniff\r\n";
    ss << "\r\n";

    return ss.str();
}

}  // namespace astrolune::gateway
