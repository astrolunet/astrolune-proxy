// Reverse tunnel connector for self-hosted Astrolune servers.
//
// Creates an outgoing reverse tunnel from a VPS/home server to an
// Astrolune proxy node.  The proxy node can then forward incoming
// client connections back through the tunnel to the local server.
//
// Features:
//   - TLS-encrypted tunnel transport
//   - HMAC-based heartbeat / keepalive
//   - Automatic failover to backup proxy nodes
//   - Challenge-response authentication
//
// Thread-per-connection model.  No exceptions across ABI boundaries;
// errors are returned via std::expected.

#ifndef ASTROLUNE_PROXY_PROXY_CONNECTOR_HPP
#define ASTROLUNE_PROXY_PROXY_CONNECTOR_HPP

#include <chrono>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::proxy {

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

constexpr uint16_t kDefaultTunnelPort      = 9443;
constexpr uint32_t kDefaultHeartbeatMs     = 15000;
constexpr uint32_t kMaxFramePayload        = 65536;
constexpr size_t   kTunnelBufferSize       = 32768;

// ---------------------------------------------------------------------------
// Tunnel frame types (wire protocol)
// ---------------------------------------------------------------------------

enum class FrameType : uint8_t {
    Heartbeat     = 0x01,
    HeartbeatAck  = 0x02,
    AuthRequest   = 0x10,
    AuthResponse  = 0x11,
    Data          = 0x20,
    OpenChannel   = 0x30,
    CloseChannel  = 0x31,
    Error         = 0xFF,
};

// ---------------------------------------------------------------------------
// Connector error codes
// ---------------------------------------------------------------------------

enum class ConnectorErrorCode {
    SocketCreateFailed,
    SocketConnectFailed,
    SocketSendFailed,
    SocketRecvFailed,
    TlsHandshakeFailed,
    TlsCertificateError,
    TlsVerificationFailed,
    AuthFailed,
    AuthChallengeInvalid,
    AuthRejected,
    HeartbeatTimeout,
    TunnelClosed,
    TunnelReadFailed,
    TunnelWriteFailed,
    FrameMalformed,
    FramePayloadTooLarge,
    ChannelOpenFailed,
    ChannelNotFound,
    ChannelLimitReached,
    FailoverExhausted,
    ConfigInvalid,
    AlreadyConnected,
    NotConnected,
    InternalError,
};

struct ConnectorError {
    ConnectorErrorCode code = ConnectorErrorCode::InternalError;
    std::string message;

    static ConnectorError make(ConnectorErrorCode c, std::string msg) {
        return ConnectorError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// ProxyEndpoint — address of a single proxy node
// ---------------------------------------------------------------------------

struct ProxyEndpoint {
    std::string host;
    uint16_t port = kDefaultTunnelPort;

    // TLS: path to CA bundle for peer verification (empty = system default).
    std::string ca_cert_path;

    // TLS: optional client certificate for mutual TLS.
    std::string client_cert_path;
    std::string client_key_path;

    [[nodiscard]] bool operator==(const ProxyEndpoint& o) const noexcept = default;
};

// ---------------------------------------------------------------------------
// ConnectorConfig — immutable after construction
// ---------------------------------------------------------------------------

struct ConnectorConfig {
    // Ordered list of proxy nodes to try.  First is primary; rest are backups.
    std::vector<ProxyEndpoint> proxy_nodes;

    // The local service to expose through the tunnel.
    std::string local_host = "127.0.0.1";
    uint16_t local_port    = 8080;

    // Authentication key shared with the proxy node.
    std::string auth_key;

    // Heartbeat interval in milliseconds (0 = disabled).
    uint32_t heartbeat_interval_ms = kDefaultHeartbeatMs;

    // How many consecutive missed heartbeats before declaring failure.
    uint32_t heartbeat_miss_limit = 3;

    // Connect timeout per attempt in milliseconds.
    uint32_t connect_timeout_ms = 10000;

    // Maximum concurrent tunnel channels (0 = unlimited).
    size_t max_channels = 0;

    // Retry delay after all nodes fail, in milliseconds.
    uint32_t retry_delay_ms = 5000;

    // Human-readable service name registered with the proxy.
    std::string service_name;

    // Unique identifier for this connector instance.
    std::string instance_id;
};

// ---------------------------------------------------------------------------
// TunnelStatus — live telemetry for the tunnel connection
// ---------------------------------------------------------------------------

struct TunnelStatus {
    bool connected = false;

    // Index into ConnectorConfig::proxy_nodes of the active node.
    size_t active_node_index = 0;

    // Round-trip time of the last successful heartbeat.
    std::chrono::milliseconds latency{0};

    // Total bytes transferred through the tunnel.
    uint64_t bytes_sent = 0;
    uint64_t bytes_received = 0;

    // Uptime since last successful connection.
    std::chrono::seconds uptime{0};

    // Number of currently open channels.
    size_t active_channels = 0;

    // Timestamp of the last heartbeat exchange.
    std::chrono::steady_clock::time_point last_heartbeat{};
};

// ---------------------------------------------------------------------------
// ServiceRegistration — result of register_service()
// ---------------------------------------------------------------------------

struct ServiceRegistration {
    std::string assigned_domain;    // e.g. "myservice.lune"
    std::string tunnel_token;       // token the proxy uses to identify this tunnel
    uint32_t    ttl_seconds = 0;    // how long the registration is valid
};

// ---------------------------------------------------------------------------
// ProxyConnector — the main reverse tunnel connector
// ---------------------------------------------------------------------------

class ProxyConnector {
public:
    ProxyConnector();
    explicit ProxyConnector(ConnectorConfig config);
    ~ProxyConnector();

    ProxyConnector(const ProxyConnector&) = delete;
    ProxyConnector& operator=(const ProxyConnector&) = delete;
    ProxyConnector(ProxyConnector&&) noexcept;
    ProxyConnector& operator=(ProxyConnector&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Establish the reverse tunnel to the proxy node.  Tries nodes in order
    // and falls back to backups on failure.
    std::expected<void, ConnectorError> connect();

    // Tear down the tunnel gracefully.
    void disconnect();

    // True when the tunnel is established and healthy.
    bool is_connected() const;

    // --- Status -----------------------------------------------------------

    // Live telemetry snapshot.
    TunnelStatus get_status() const;

    // --- Service registration ---------------------------------------------

    // Register the local service with the proxy node so clients can reach it.
    std::expected<ServiceRegistration, ConnectorError> register_service(
        std::string_view service_name);

    // --- Configuration (must be set before connect()) ---------------------

    void set_config(ConnectorConfig config);
    const ConnectorConfig& config() const;

    // --- Callbacks --------------------------------------------------------

    // Invoked when the tunnel transitions from disconnected to connected.
    void on_connected(std::function<void()> callback);

    // Invoked when the tunnel disconnects (before automatic retry).
    void on_disconnected(std::function<void(ConnectorError)> callback);

    // Invoked when a new channel is opened by the proxy node.
    // The callback receives (channel_id, local_fd) — the local_fd is the
    // socket connected to the local service.  The callback should take
    // ownership of the fd and relay data.
    void on_channel_open(std::function<void(uint32_t, int)> callback);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// Wire-level frame helpers (public for testability)
// ---------------------------------------------------------------------------

// A decoded tunnel frame.
struct TunnelFrame {
    FrameType type = FrameType::Error;
    uint32_t channel_id = 0;
    std::vector<uint8_t> payload;
};

// Serialize a frame into bytes.
std::vector<uint8_t> serialize_frame(const TunnelFrame& frame);

// Deserialize bytes into a frame.  Returns an error if the data is malformed.
std::expected<TunnelFrame, ConnectorError> deserialize_frame(
    const uint8_t* data, size_t len);

// Compute HMAC-SHA256 of a challenge string using the shared auth key.
std::vector<uint8_t> compute_hmac(const std::string& key,
                                  std::string_view data);

}  // namespace astrolune::proxy

#endif  // ASTROLUNE_PROXY_PROXY_CONNECTOR_HPP
