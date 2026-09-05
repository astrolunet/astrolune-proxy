// SOCKS5 and HTTP CONNECT proxy for the Astrolune Connect client.
//
// Listens on a local port (default 1080) for SOCKS5 or HTTP CONNECT
// tunnel requests and forwards TCP traffic through the configured
// upstream proxy (Astrolune network node) or directly to the target.
//
// Thread-per-connection model.  No exceptions across ABI boundaries;
// errors are returned via std::expected.

#ifndef ASTROLUNE_PROXY_SOCKS5_PROXY_HPP
#define ASTROLUNE_PROXY_SOCKS5_PROXY_HPP

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace astrolune::proxy {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint16_t kDefaultSocksPort = 1080;
constexpr size_t   kBufferSize = 8192;

// ---------------------------------------------------------------------------
// Authentication method (RFC 1928)
// ---------------------------------------------------------------------------

enum class AuthMethod : uint8_t {
    NoAuth       = 0x00,
    UsernamePass = 0x02,
    NoAcceptable = 0xFF,
};

// ---------------------------------------------------------------------------
// SOCKS5 request commands
// ---------------------------------------------------------------------------

enum class SocksCommand : uint8_t {
    Connect       = 0x01,
    Bind          = 0x02,
    UdpAssociate  = 0x03,
};

// ---------------------------------------------------------------------------
// SOCKS5 address types
// ---------------------------------------------------------------------------

enum class AddressType : uint8_t {
    IPv4   = 0x01,
    Domain = 0x03,
    IPv6   = 0x04,
};

// ---------------------------------------------------------------------------
// ProxyConfig — immutable after construction
// ---------------------------------------------------------------------------

struct ProxyConfig {
    uint16_t listen_port = kDefaultSocksPort;

    // Optional upstream proxy ("host:port").  Empty means direct connection.
    std::string upstream_proxy;

    // Authentication credentials.  Empty username means no auth required.
    std::string auth_username;
    std::string auth_password;

    // Connection timeout in milliseconds.
    uint32_t connect_timeout_ms = 10000;

    // Maximum simultaneous connections (0 = unlimited).
    size_t max_connections = 0;
};

// ---------------------------------------------------------------------------
// Connection — tracks one active proxied session
// ---------------------------------------------------------------------------

struct Connection {
    uint64_t   id = 0;
    int        client_fd = -1;
    int        target_fd = -1;
    std::string target_host;
    uint16_t    target_port = 0;
    bool        authenticated = false;
    bool        closed = false;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_active;
};

// ---------------------------------------------------------------------------
// ProxyError — non-exception error type
// ---------------------------------------------------------------------------

enum class ProxyErrorCode {
    SocketCreateFailed,
    SocketBindFailed,
    SocketListenFailed,
    SocketAcceptFailed,
    SocketConnectFailed,
    SocketSendFailed,
    SocketRecvFailed,
    SocksHandshakeFailed,
    SocksUnsupportedVersion,
    SocksUnsupportedCommand,
    SocksUnsupportedAddressType,
    AuthRequired,
    AuthFailed,
    AuthNotExpected,
    HttpConnectMalformed,
    UpstreamConnectFailed,
    UpstreamHandshakeFailed,
    ConnectionClosed,
    ConnectionLimitReached,
    AlreadyRunning,
    NotRunning,
    InternalError,
};

struct ProxyError {
    ProxyErrorCode code = ProxyErrorCode::InternalError;
    std::string message;

    static ProxyError make(ProxyErrorCode c, std::string msg) {
        return ProxyError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// Socks5Proxy — the main proxy server
// ---------------------------------------------------------------------------

class Socks5Proxy {
public:
    Socks5Proxy();
    explicit Socks5Proxy(ProxyConfig config);
    ~Socks5Proxy();

    Socks5Proxy(const Socks5Proxy&) = delete;
    Socks5Proxy& operator=(const Socks5Proxy&) = delete;
    Socks5Proxy(Socks5Proxy&&) noexcept;
    Socks5Proxy& operator=(Socks5Proxy&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Start listening.  Spawns the accept thread.
    std::expected<void, ProxyError> start();

    // Stop the proxy and close all active connections.
    void stop();

    // True when the accept loop is running.
    bool is_running() const;

    // --- Configuration (must be set before start()) -----------------------

    void set_config(ProxyConfig config);
    const ProxyConfig& config() const;

    // --- Connection tracking -----------------------------------------------

    // Snapshot of currently active connections.
    std::vector<Connection> active_connections() const;

    // Number of active connections.
    size_t connection_count() const;

    // --- Wire-level helpers (public for testability) -----------------------

    // Perform the SOCKS5 greeting handshake on `fd`.
    // Returns the method chosen by the server.
    static std::expected<AuthMethod, ProxyError> socks5_greeting(
        int fd, const ProxyConfig& cfg);

    // Perform username/password sub-negotiation (RFC 1929).
    static std::expected<void, ProxyError> socks5_auth_userpass(
        int fd, std::string_view username, std::string_view password);

    // Read and validate a SOCKS5 CONNECT request.  Returns the
    // target host and port on success.
    static std::expected<std::pair<std::string, uint16_t>, ProxyError>
    socks5_connect_request(int fd);

    // Send a SOCKS5 reply with the given status.
    static std::expected<void, ProxyError> socks5_send_reply(
        int fd, uint8_t status);

    // Detect whether a buffer starts with an HTTP CONNECT request.
    static bool is_http_connect(const uint8_t* data, size_t len);

    // Parse the host:port from an HTTP CONNECT line.
    static std::expected<std::pair<std::string, uint16_t>, ProxyError>
    parse_http_connect(const uint8_t* data, size_t len);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// Read exactly `n` bytes from a file descriptor into `buf`.
// Returns the number of bytes read or an error.
std::expected<size_t, ProxyError> read_exact(int fd, uint8_t* buf, size_t n);

// Write exactly `n` bytes from `buf` to a file descriptor.
std::expected<size_t, ProxyError> write_exact(int fd, const uint8_t* buf, size_t n);

// Set a socket to non-blocking mode.
std::expected<void, ProxyError> set_nonblocking(int fd);

// Set SO_KEEPALIVE on a socket.
std::expected<void, ProxyError> set_keepalive(int fd);

}  // namespace astrolune::proxy

#endif  // ASTROLUNE_PROXY_SOCKS5_PROXY_HPP
