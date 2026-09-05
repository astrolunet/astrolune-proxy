// astrolune/tools/ecosystem/proxy/proxy_connector.cpp
//
// Implementation of the reverse tunnel connector.
//
// Wire protocol:
//   Each frame is:
//     [1 byte]  frame type
//     [4 bytes] channel ID (network order)
//     [4 bytes] payload length (network order, max 64KB)
//     [N bytes] payload
//
// Authentication flow:
//   1. Client sends AuthRequest with HMAC-SHA256(timestamp || nonce, auth_key).
//   2. Server verifies the HMAC and sends AuthResponse with status + session token.
//
// Heartbeat:
//   Client sends Heartbeat at the configured interval.  Server replies with
//   HeartbeatAck.  After heartbeat_miss_limit missed acks the tunnel is
//   considered dead and failover begins.

#include "proxy_connector.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>

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

// OpenSSL (optional — guarded by ASTROLUNE_USE_OPENSSL)
#ifdef ASTROLUNE_USE_OPENSSL
  #include <openssl/err.h>
  #include <openssl/ssl.h>
  #include <openssl/hmac.h>
  #include <openssl/x509v3.h>
#endif

namespace astrolune::proxy {

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

static constexpr uint32_t kFrameHeaderSize = 9;  // type(1) + channel(4) + len(4)

// ---------------------------------------------------------------------------
// TLS context (thin wrapper — only compiled when OpenSSL is available)
// ---------------------------------------------------------------------------

#ifdef ASTROLUNE_USE_OPENSSL

struct TlsContext {
    SSL_CTX* ctx = nullptr;

    TlsContext() = default;
    ~TlsContext() { if (ctx) SSL_CTX_free(ctx); }

    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;
    TlsContext(TlsContext&& o) noexcept : ctx(o.ctx) { o.ctx = nullptr; }
    TlsContext& operator=(TlsContext&& o) noexcept {
        if (this != &o) { if (ctx) SSL_CTX_free(ctx); ctx = o.ctx; o.ctx = nullptr; }
        return *this;
    }

    std::expected<void, ConnectorError> init(const ProxyEndpoint& ep) {
        ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsHandshakeFailed,
                "SSL_CTX_new failed"));
        }

        // Set minimum TLS 1.2
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

        // Load CA certificate
        if (!ep.ca_cert_path.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, ep.ca_cert_path.c_str(), nullptr) != 1) {
                return std::unexpected(ConnectorError::make(
                    ConnectorErrorCode::TlsCertificateError,
                    "failed to load CA cert: " + ep.ca_cert_path));
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }

        // Load client certificate for mutual TLS
        if (!ep.client_cert_path.empty() && !ep.client_key_path.empty()) {
            if (SSL_CTX_use_certificate_file(ctx, ep.client_cert_path.c_str(),
                                              SSL_FILETYPE_PEM) != 1) {
                return std::unexpected(ConnectorError::make(
                    ConnectorErrorCode::TlsCertificateError,
                    "failed to load client cert"));
            }
            if (SSL_CTX_use_PrivateKey_file(ctx, ep.client_key_path.c_str(),
                                             SSL_FILETYPE_PEM) != 1) {
                return std::unexpected(ConnectorError::make(
                    ConnectorErrorCode::TlsCertificateError,
                    "failed to load client key"));
            }
            if (SSL_CTX_check_private_key(ctx) != 1) {
                return std::unexpected(ConnectorError::make(
                    ConnectorErrorCode::TlsCertificateError,
                    "client cert/key mismatch"));
            }
        }

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        return {};
    }
};

struct TlsConnection {
    SSL* ssl = nullptr;

    ~TlsConnection() { if (ssl) SSL_free(ssl); }

    TlsConnection(const TlsConnection&) = delete;
    TlsConnection& operator=(const TlsConnection&) = delete;
    TlsConnection(TlsConnection&& o) noexcept : ssl(o.ssl) { o.ssl = nullptr; }
    TlsConnection& operator=(TlsConnection&& o) noexcept {
        if (this != &o) { if (ssl) SSL_free(ssl); ssl = o.ssl; o.ssl = nullptr; }
        return *this;
    }

    std::expected<void, ConnectorError> handshake(sock_t fd, SSL_CTX* ctx,
                                                   const ProxyEndpoint& ep) {
        ssl = SSL_new(ctx);
        if (!ssl) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsHandshakeFailed, "SSL_new failed"));
        }

        SSL_set_fd(ssl, static_cast<int>(fd));

        // Set SNI hostname
        SSL_set_tlsext_host_name(ssl, ep.host.c_str());

        if (SSL_connect(ssl) != 1) {
            unsigned long err = ERR_get_error();
            char buf[256]{};
            ERR_error_string_n(err, buf, sizeof(buf));
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsHandshakeFailed,
                std::string("TLS connect failed: ") + buf));
        }

        // Verify peer certificate
        X509* peer = SSL_get_peer_certificate(ssl);
        if (!peer) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsVerificationFailed,
                "no peer certificate presented"));
        }

        long verify = SSL_get_verify_result(ssl);
        X509_free(peer);
        if (verify != X509_V_OK) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsVerificationFailed,
                "certificate verification failed: " +
                    std::string(X509_verify_cert_error_string(verify))));
        }

        return {};
    }

    std::expected<size_t, ConnectorError> send(const uint8_t* data, size_t len) {
        int n = SSL_write(ssl, data, static_cast<int>(len));
        if (n <= 0) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TlsHandshakeFailed, "TLS write failed"));
        }
        return static_cast<size_t>(n);
    }

    std::expected<size_t, ConnectorError> recv(uint8_t* buf, size_t len) {
        int n = SSL_read(ssl, buf, static_cast<int>(len));
        if (n <= 0) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TunnelReadFailed, "TLS read failed"));
        }
        return static_cast<size_t>(n);
    }
};

#endif  // ASTROLUNE_USE_OPENSSL

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

static std::expected<size_t, ConnectorError> raw_send(sock_t fd, const uint8_t* data, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto sent = ::send(fd, reinterpret_cast<const char*>(data + total),
                           static_cast<int>(n - total), 0);
        if (sent <= 0) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::SocketSendFailed,
                sent == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(sent);
    }
    return total;
}

static std::expected<size_t, ConnectorError> raw_recv(sock_t fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto got = ::recv(fd, reinterpret_cast<char*>(buf + total),
                          static_cast<int>(n - total), 0);
        if (got <= 0) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::TunnelReadFailed,
                got == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(got);
    }
    return total;
}

// ---------------------------------------------------------------------------
// Frame serialization / deserialization
// ---------------------------------------------------------------------------

std::vector<uint8_t> serialize_frame(const TunnelFrame& frame) {
    std::vector<uint8_t> buf;
    buf.reserve(kFrameHeaderSize + frame.payload.size());

    buf.push_back(static_cast<uint8_t>(frame.type));

    // channel_id — network byte order
    uint32_t ch = htonl(frame.channel_id);
    auto* chp = reinterpret_cast<const uint8_t*>(&ch);
    buf.insert(buf.end(), chp, chp + 4);

    // payload length — network byte order
    uint32_t pl = htonl(static_cast<uint32_t>(frame.payload.size()));
    auto* plp = reinterpret_cast<const uint8_t*>(&pl);
    buf.insert(buf.end(), plp, plp + 4);

    // payload
    buf.insert(buf.end(), frame.payload.begin(), frame.payload.end());

    return buf;
}

std::expected<TunnelFrame, ConnectorError> deserialize_frame(
    const uint8_t* data, size_t len)
{
    if (len < kFrameHeaderSize) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::FrameMalformed,
            "frame too short: " + std::to_string(len)));
    }

    TunnelFrame frame{};
    frame.type = static_cast<FrameType>(data[0]);

    uint32_t ch{};
    std::memcpy(&ch, data + 1, 4);
    frame.channel_id = ntohl(ch);

    uint32_t pl{};
    std::memcpy(&pl, data + 5, 4);
    uint32_t payload_len = ntohl(pl);

    if (payload_len > kMaxFramePayload) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::FramePayloadTooLarge,
            "payload too large: " + std::to_string(payload_len)));
    }

    if (len < kFrameHeaderSize + payload_len) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::FrameMalformed,
            "frame truncated"));
    }

    frame.payload.assign(data + kFrameHeaderSize,
                         data + kFrameHeaderSize + payload_len);
    return frame;
}

// ---------------------------------------------------------------------------
// HMAC helper
// ---------------------------------------------------------------------------

std::vector<uint8_t> compute_hmac(const std::string& key, std::string_view data) {
#ifdef ASTROLUNE_USE_OPENSSL
    unsigned int len = 0;
    unsigned char* out = HMAC(EVP_sha256(),
                              key.data(), static_cast<int>(key.size()),
                              reinterpret_cast<const unsigned char*>(data.data()),
                              data.size(), nullptr, &len);
    if (!out) return {};
    return std::vector<uint8_t>(out, out + len);
#else
    // Stub when OpenSSL is not linked — returns 32 zero bytes.
    return std::vector<uint8_t>(32, 0);
#endif
}

// ---------------------------------------------------------------------------
// ProxyConnector::Impl
// ---------------------------------------------------------------------------

struct ProxyConnector::Impl {
    ConnectorConfig cfg;
    std::atomic<bool> connected{false};
    std::atomic<bool> stopping{false};

    // Active socket + TLS state
    sock_t tunnel_fd = kInvalidSock;
#ifdef ASTROLUNE_USE_OPENSSL
    TlsContext tls_ctx;
    TlsConnection tls_conn;
#endif

    // Thread management
    std::thread connect_thread;
    std::thread heartbeat_thread;
    std::thread relay_thread;

    // Telemetry
    mutable std::mutex status_mu;
    TunnelStatus status{};

    // Channel tracking
    mutable std::mutex channel_mu;
    std::atomic<uint32_t> next_channel_id{1};

    // Callbacks
    std::function<void()> on_connected_cb;
    std::function<void(ConnectorError)> on_disconnected_cb;
    std::function<void(uint32_t, int)> on_channel_open_cb;

    // --- Resolve and connect to a single endpoint -------------------------

    std::expected<sock_t, ConnectorError> connect_endpoint(const ProxyEndpoint& ep) {
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* res = nullptr;
        std::string port_str = std::to_string(ep.port);
        int rc = ::getaddrinfo(ep.host.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0 || !res) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::SocketConnectFailed,
                "getaddrinfo failed for " + ep.host));
        }

        sock_t fd = kInvalidSock;
        for (addrinfo* p = res; p; p = p->ai_next) {
            fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (fd == kInvalidSock) continue;

            // Set connect timeout via non-blocking + select
            u_long nonblock = 1;
#ifdef _WIN32
            ::ioctlsocket(fd, FIONBIO, &nonblock);
#else
            ::fcntl(fd, F_SETFL, O_NONBLOCK);
#endif

            int connect_res = ::connect(fd, p->ai_addr, p->ai_addrlen);
            if (connect_res != 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
                if (errno == EINPROGRESS) {
#endif
                    fd_set writefds;
                    FD_ZERO(&writefds);
                    FD_SET(fd, &writefds);

                    timeval tv{};
                    tv.tv_sec = cfg.connect_timeout_ms / 1000;
                    tv.tv_usec = (cfg.connect_timeout_ms % 1000) * 1000;

                    int sel = ::select(static_cast<int>(fd) + 1,
                                       nullptr, &writefds, nullptr, &tv);
                    if (sel <= 0) {
                        CLOSE_SOCKET(fd);
                        fd = kInvalidSock;
                        continue;
                    }

                    int err = 0;
                    socklen_t errlen = sizeof(err);
                    ::getsockopt(fd, SOL_SOCKET, SO_ERROR,
                                 reinterpret_cast<char*>(&err), &errlen);
                    if (err != 0) {
                        CLOSE_SOCKET(fd);
                        fd = kInvalidSock;
                        continue;
                    }
                } else {
                    CLOSE_SOCKET(fd);
                    fd = kInvalidSock;
                    continue;
                }
            }

            // Restore blocking mode
            nonblock = 0;
#ifdef _WIN32
            ::ioctlsocket(fd, FIONBIO, &nonblock);
#else
            int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags >= 0) ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
#endif

            break;
        }
        ::freeaddrinfo(res);

        if (fd == kInvalidSock) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::SocketConnectFailed,
                "connect failed to " + ep.host + ":" + port_str));
        }

        // Enable TCP keepalive
        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                     reinterpret_cast<const char*>(&yes), sizeof(yes));

        return fd;
    }

    // --- TLS handshake on an established socket ---------------------------

    std::expected<void, ConnectorError> tls_handshake(sock_t fd,
                                                       const ProxyEndpoint& ep) {
#ifdef ASTROLUNE_USE_OPENSSL
        auto tls_res = tls_ctx.init(ep);
        if (!tls_res) return tls_res;

        tls_conn = TlsConnection{};
        return tls_conn.handshake(fd, tls_ctx.ctx, ep);
#else
        (void)fd;
        (void)ep;
        return {};  // No TLS — plaintext tunnel (not recommended)
#endif
    }

    // --- Send / recv through TLS or plaintext -----------------------------

    std::expected<size_t, ConnectorError> tunnel_send(const uint8_t* data, size_t len) {
#ifdef ASTROLUNE_USE_OPENSSL
        if (tls_conn.ssl) return tls_conn.send(data, len);
#endif
        return raw_send(tunnel_fd, data, len);
    }

    std::expected<size_t, ConnectorError> tunnel_recv(uint8_t* buf, size_t len) {
#ifdef ASTROLUNE_USE_OPENSSL
        if (tls_conn.ssl) return tls_conn.recv(buf, len);
#endif
        return raw_recv(tunnel_fd, buf, len);
    }

    // --- Authentication ---------------------------------------------------

    std::expected<void, ConnectorError> perform_authentication() {
        // Build challenge: timestamp + random nonce
        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        std::mt19937_64 rng{std::random_device{}()};
        uint64_t nonce = rng();
        uint64_t nonce2 = rng();

        std::ostringstream challenge;
        challenge << ts << ":" << std::hex << nonce << nonce2;
        std::string challenge_str = challenge.str();

        // Compute HMAC
        auto hmac = compute_hmac(cfg.auth_key, challenge_str);

        // Build AuthRequest frame
        // payload layout: [challenge_len:4][challenge][hmac_len:4][hmac]
        uint32_t cl = htonl(static_cast<uint32_t>(challenge_str.size()));
        uint32_t hl = htonl(static_cast<uint32_t>(hmac.size()));

        std::vector<uint8_t> payload;
        payload.reserve(8 + challenge_str.size() + hmac.size());
        auto* cp = reinterpret_cast<const uint8_t*>(&cl);
        payload.insert(payload.end(), cp, cp + 4);
        payload.insert(payload.end(), challenge_str.begin(), challenge_str.end());
        auto* hp = reinterpret_cast<const uint8_t*>(&hl);
        payload.insert(payload.end(), hp, hp + 4);
        payload.insert(payload.end(), hmac.begin(), hmac.end());

        TunnelFrame auth_frame{};
        auth_frame.type = FrameType::AuthRequest;
        auth_frame.payload = std::move(payload);

        auto wire = serialize_frame(auth_frame);
        auto sr = tunnel_send(wire.data(), wire.size());
        if (!sr) return std::unexpected(sr.error());

        // Read AuthResponse
        auto resp = recv_frame();
        if (!resp) return std::unexpected(resp.error());

        if (resp->type != FrameType::AuthResponse || resp->payload.size() < 1) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::AuthFailed,
                "unexpected response to auth request"));
        }

        uint8_t status = resp->payload[0];
        if (status != 0) {
            std::string reason(resp->payload.begin() + 1, resp->payload.end());
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::AuthRejected,
                "auth rejected: " + reason));
        }

        return {};
    }

    // --- Receive a single frame -------------------------------------------

    std::expected<TunnelFrame, ConnectorError> recv_frame() {
        uint8_t hdr[kFrameHeaderSize]{};
        auto hr = tunnel_recv(hdr, kFrameHeaderSize);
        if (!hr) return std::unexpected(hr.error());

        uint32_t payload_len{};
        std::memcpy(&payload_len, hdr + 5, 4);
        payload_len = ntohl(payload_len);

        if (payload_len > kMaxFramePayload) {
            return std::unexpected(ConnectorError::make(
                ConnectorErrorCode::FramePayloadTooLarge,
                "payload too large: " + std::to_string(payload_len)));
        }

        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0) {
            auto pr = tunnel_recv(payload.data(), payload_len);
            if (!pr) return std::unexpected(pr.error());
        }

        // Reconstruct full frame for deserialization
        std::vector<uint8_t> full_frame(kFrameHeaderSize + payload_len);
        std::memcpy(full_frame.data(), hdr, kFrameHeaderSize);
        std::memcpy(full_frame.data() + kFrameHeaderSize, payload.data(), payload_len);

        return deserialize_frame(full_frame.data(), full_frame.size());
    }

    // --- Send a frame -----------------------------------------------------

    std::expected<void, ConnectorError> send_frame(const TunnelFrame& frame) {
        auto wire = serialize_frame(frame);
        auto sr = tunnel_send(wire.data(), wire.size());
        if (!sr) return std::unexpected(sr.error());
        return {};
    }

    // --- Heartbeat loop ---------------------------------------------------

    void heartbeat_loop() {
        while (!stopping.load(std::memory_order_relaxed)) {
            // Sleep in small increments so we can respond to stop quickly
            for (uint32_t i = 0;
                 i < cfg.heartbeat_interval_ms && !stopping.load(std::memory_order_relaxed);
                 i += 200) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (stopping.load(std::memory_order_relaxed)) break;
            if (!connected.load(std::memory_order_relaxed)) continue;

            // Send heartbeat
            TunnelFrame hb{};
            hb.type = FrameType::Heartbeat;
            auto send_res = send_frame(hb);
            if (!send_res) {
                handle_tunnel_failure(send_res.error());
                break;
            }

            // Wait for ack (with a short timeout)
            // In production, use a proper timed recv.  Here we use a short sleep
            // and check if the relay thread already handled the ack.
            auto deadline = std::chrono::steady_clock::now() +
                             std::chrono::milliseconds(cfg.connect_timeout_ms / 2);

            // The ack is handled by the relay thread via recv_frame().
            // We just track missed heartbeats in status.
            {
                std::lock_guard lock(status_mu);
                auto since = std::chrono::steady_clock::now() - status.last_heartbeat;
                if (status.last_heartbeat != std::chrono::steady_clock::time_point{} &&
                    since > std::chrono::milliseconds(
                        cfg.heartbeat_interval_ms * cfg.heartbeat_miss_limit)) {
                    handle_tunnel_failure(ConnectorError::make(
                        ConnectorErrorCode::HeartbeatTimeout,
                        "heartbeat timeout"));
                    break;
                }
            }
        }
    }

    // --- Relay loop (receives frames from proxy, dispatches) ---------------

    void relay_loop() {
        while (!stopping.load(std::memory_order_relaxed)) {
            if (!connected.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            auto frame = recv_frame();
            if (!frame) {
                handle_tunnel_failure(frame.error());
                break;
            }

            switch (frame->type) {
            case FrameType::HeartbeatAck: {
                auto now = std::chrono::steady_clock::now();
                std::lock_guard lock(status_mu);
                if (status.last_heartbeat != std::chrono::steady_clock::time_point{}) {
                    status.latency = std::chrono::duration_cast<std::chrono::milliseconds>(
                        now - status.last_heartbeat);
                }
                status.last_heartbeat = now;
                break;
            }

            case FrameType::Heartbeat: {
                // Proxy is pinging us — respond
                TunnelFrame ack{};
                ack.type = FrameType::HeartbeatAck;
                send_frame(ack);
                break;
            }

            case FrameType::OpenChannel: {
                handle_open_channel(*frame);
                break;
            }

            case FrameType::CloseChannel: {
                std::lock_guard lock(channel_mu);
                // Channel cleanup is handled by the relay thread closing its fd.
                break;
            }

            case FrameType::Data: {
                // Data for an existing channel — dispatch to the channel relay.
                // In a full implementation this would write to a per-channel pipe.
                break;
            }

            default:
                break;
            }
        }
    }

    // --- Handle incoming channel open from proxy ---------------------------

    void handle_open_channel(const TunnelFrame& frame) {
        if (!on_channel_open_cb) return;

        // Connect to local service
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* res = nullptr;
        std::string port_str = std::to_string(cfg.local_port);
        int rc = ::getaddrinfo(cfg.local_host.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0 || !res) {
            // Send CloseChannel back
            TunnelFrame close_frame{};
            close_frame.type = FrameType::CloseChannel;
            close_frame.channel_id = frame.channel_id;
            send_frame(close_frame);
            return;
        }

        sock_t local_fd = kInvalidSock;
        for (addrinfo* p = res; p; p = p->ai_next) {
            local_fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (local_fd == kInvalidSock) continue;
            if (::connect(local_fd, p->ai_addr, p->ai_addrlen) == 0) break;
            CLOSE_SOCKET(local_fd);
            local_fd = kInvalidSock;
        }
        ::freeaddrinfo(res);

        if (local_fd == kInvalidSock) {
            TunnelFrame close_frame{};
            close_frame.type = FrameType::CloseChannel;
            close_frame.channel_id = frame.channel_id;
            send_frame(close_frame);
            return;
        }

        // Track channel
        {
            std::lock_guard lock(channel_mu);
            std::lock_guard slock(status_mu);
            status.active_channels++;
        }

        // Invoke callback — caller takes ownership of local_fd
        on_channel_open_cb(frame.channel_id, local_fd);
    }

    // --- Tunnel failure handler -------------------------------------------

    void handle_tunnel_failure(ConnectorError err) {
        bool was_connected = connected.exchange(false, std::memory_order_acq_rel);
        if (!was_connected) return;

        // Close socket
        if (tunnel_fd != kInvalidSock) {
            CLOSE_SOCKET(tunnel_fd);
            tunnel_fd = kInvalidSock;
        }

#ifdef ASTROLUNE_USE_OPENSSL
        if (tls_conn.ssl) {
            SSL_free(tls_conn.ssl);
            tls_conn.ssl = nullptr;
        }
#endif

        {
            std::lock_guard lock(status_mu);
            status.connected = false;
            status.active_channels = 0;
        }

        if (on_disconnected_cb) {
            on_disconnected_cb(std::move(err));
        }
    }

    // --- Main connection loop (with failover) -----------------------------

    void connect_loop() {
        while (!stopping.load(std::memory_order_relaxed)) {
            bool success = false;

            for (size_t i = 0; i < cfg.proxy_nodes.size(); ++i) {
                if (stopping.load(std::memory_order_relaxed)) return;

                const auto& ep = cfg.proxy_nodes[i];

                // TCP connect
                auto fd_res = connect_endpoint(ep);
                if (!fd_res) {
                    continue;
                }
                tunnel_fd = *fd_res;

                // TLS handshake
                auto tls_res = tls_handshake(tunnel_fd, ep);
                if (!tls_res) {
                    CLOSE_SOCKET(tunnel_fd);
                    tunnel_fd = kInvalidSock;
                    continue;
                }

                // Authentication
                auto auth_res = perform_authentication();
                if (!auth_res) {
                    CLOSE_SOCKET(tunnel_fd);
                    tunnel_fd = kInvalidSock;
                    continue;
                }

                // Connected!
                connected.store(true, std::memory_order_release);
                {
                    std::lock_guard lock(status_mu);
                    status.connected = true;
                    status.active_node_index = i;
                    status.last_heartbeat = std::chrono::steady_clock::now();
                    status.uptime = std::chrono::seconds{0};
                }

                if (on_connected_cb) on_connected_cb();
                success = true;
                break;
            }

            if (!success) {
                // All nodes failed — wait before retrying
                if (cfg.retry_delay_ms > 0) {
                    auto delay = std::chrono::milliseconds(cfg.retry_delay_ms);
                    auto step = std::chrono::milliseconds(200);
                    while (!stopping.load(std::memory_order_relaxed) && delay.count() > 0) {
                        std::this_thread::sleep_for(
                            std::min(step, delay));
                        delay -= step;
                    }
                }
                continue;
            }

            // Start heartbeat + relay threads
            heartbeat_thread = std::thread(&Impl::heartbeat_loop, this);
            relay_thread = std::thread(&Impl::relay_loop, this);

            // Wait for either thread to exit (tunnel failure)
            if (heartbeat_thread.joinable()) heartbeat_thread.join();
            if (relay_thread.joinable()) relay_thread.join();
        }
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

ProxyConnector::ProxyConnector()
    : impl_(std::make_unique<Impl>()) {}

ProxyConnector::ProxyConnector(ConnectorConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}

ProxyConnector::~ProxyConnector() {
    disconnect();
}

ProxyConnector::ProxyConnector(ProxyConnector&&) noexcept = default;
ProxyConnector& ProxyConnector::operator=(ProxyConnector&&) noexcept = default;

std::expected<void, ConnectorError> ProxyConnector::connect() {
    if (impl_->connected.load(std::memory_order_acquire)) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::AlreadyConnected, "tunnel already connected"));
    }

    if (impl_->cfg.proxy_nodes.empty()) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::ConfigInvalid, "no proxy nodes configured"));
    }

    impl_->stopping.store(false, std::memory_order_release);
    impl_->connect_thread = std::thread(&Impl::connect_loop, impl_.get());

    // Give the connect thread a moment to establish the tunnel
    auto deadline = std::chrono::steady_clock::now() +
                     std::chrono::milliseconds(impl_->cfg.connect_timeout_ms * 2);

    while (!impl_->connected.load(std::memory_order_acquire)) {
        if (std::chrono::steady_clock::now() > deadline) {
            // Let the thread continue in background for retry — don't block forever.
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return {};
}

void ProxyConnector::disconnect() {
    impl_->stopping.store(true, std::memory_order_release);

    // Close the tunnel socket to unblock any blocking I/O
    if (impl_->tunnel_fd != kInvalidSock) {
        CLOSE_SOCKET(impl_->tunnel_fd);
        impl_->tunnel_fd = kInvalidSock;
    }

    if (impl_->connect_thread.joinable()) impl_->connect_thread.join();
    if (impl_->heartbeat_thread.joinable()) impl_->heartbeat_thread.join();
    if (impl_->relay_thread.joinable()) impl_->relay_thread.join();

    impl_->connected.store(false, std::memory_order_release);

    {
        std::lock_guard lock(impl_->status_mu);
        impl_->status = TunnelStatus{};
    }
}

bool ProxyConnector::is_connected() const {
    return impl_->connected.load(std::memory_order_acquire);
}

TunnelStatus ProxyConnector::get_status() const {
    std::lock_guard lock(impl_->status_mu);
    return impl_->status;
}

std::expected<ServiceRegistration, ConnectorError>
ProxyConnector::register_service(std::string_view service_name) {
    if (!impl_->connected.load(std::memory_order_acquire)) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::NotConnected, "tunnel not connected"));
    }

    // Build the registration payload
    // layout: [service_name_len:4][service_name][instance_id_len:4][instance_id]
    uint32_t snl = htonl(static_cast<uint32_t>(service_name.size()));
    uint32_t iil = htonl(static_cast<uint32_t>(impl_->cfg.instance_id.size()));

    std::vector<uint8_t> payload;
    payload.reserve(8 + service_name.size() + impl_->cfg.instance_id.size());

    auto* sp = reinterpret_cast<const uint8_t*>(&snl);
    payload.insert(payload.end(), sp, sp + 4);
    payload.insert(payload.end(), service_name.begin(), service_name.end());

    auto* ip = reinterpret_cast<const uint8_t*>(&iil);
    payload.insert(payload.end(), ip, ip + 4);
    payload.insert(payload.end(),
                   impl_->cfg.instance_id.begin(),
                   impl_->cfg.instance_id.end());

    TunnelFrame reg_frame{};
    reg_frame.type = FrameType::Data;  // Data frame carries registration
    reg_frame.payload = std::move(payload);

    auto send_res = impl_->send_frame(reg_frame);
    if (!send_res) return std::unexpected(send_res.error());

    // Wait for response
    auto resp = impl_->recv_frame();
    if (!resp) return std::unexpected(resp.error());

    if (resp->type != FrameType::Data || resp->payload.size() < 8) {
        return std::unexpected(ConnectorError::make(
            ConnectorErrorCode::FrameMalformed,
            "invalid registration response"));
    }

    // Parse response: [domain_len:4][domain][token_len:4][token][ttl:4]
    const uint8_t* p = resp->payload.data();
    const uint8_t* end = resp->payload.data() + resp->payload.size();

    uint32_t domain_len{};
    std::memcpy(&domain_len, p, 4);
    domain_len = ntohl(domain_len);
    p += 4;

    if (p + domain_len > end) return std::unexpected(ConnectorError::make(
        ConnectorErrorCode::FrameMalformed, "truncated domain in response"));

    std::string domain(reinterpret_cast<const char*>(p), domain_len);
    p += domain_len;

    if (p + 4 > end) return std::unexpected(ConnectorError::make(
        ConnectorErrorCode::FrameMalformed, "truncated token length"));

    uint32_t token_len{};
    std::memcpy(&token_len, p, 4);
    token_len = ntohl(token_len);
    p += 4;

    if (p + token_len > end) return std::unexpected(ConnectorError::make(
        ConnectorErrorCode::FrameMalformed, "truncated token"));

    std::string token(reinterpret_cast<const char*>(p), token_len);
    p += token_len;

    uint32_t ttl = 0;
    if (p + 4 <= end) {
        std::memcpy(&ttl, p, 4);
        ttl = ntohl(ttl);
    }

    ServiceRegistration reg;
    reg.assigned_domain = std::move(domain);
    reg.tunnel_token = std::move(token);
    reg.ttl_seconds = ttl;

    return reg;
}

void ProxyConnector::set_config(ConnectorConfig config) {
    impl_->cfg = std::move(config);
}

const ConnectorConfig& ProxyConnector::config() const {
    return impl_->cfg;
}

void ProxyConnector::on_connected(std::function<void()> callback) {
    impl_->on_connected_cb = std::move(callback);
}

void ProxyConnector::on_disconnected(std::function<void(ConnectorError)> callback) {
    impl_->on_disconnected_cb = std::move(callback);
}

void ProxyConnector::on_channel_open(std::function<void(uint32_t, int)> callback) {
    impl_->on_channel_open_cb = std::move(callback);
}

}  // namespace astrolune::proxy
