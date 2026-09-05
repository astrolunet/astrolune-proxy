// Astrolune Connect CLI — main entry point for the client.
//
// Starts and manages the local DNS resolver and SOCKS5 proxy that provide
// DNS resolution, network connectivity, and split-DNS routing for .lune
// domains.  Configuration is read from a TOML file (astrolune-connect.toml).
//
// Design constraints:
//   - No exceptions across ABI boundaries; errors return std::expected.
//   - Thread-safe; components run on their own threads.
//   - Lifetime managed through RAII and pImpl for ABI stability.

#ifndef ASTROLUNE_CONNECT_ASTROLUNE_CONNECT_HPP
#define ASTROLUNE_CONNECT_ASTROLUNE_CONNECT_HPP

#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace astrolune::connect {

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

constexpr int kConnectMajorVersion = 0;
constexpr int kConnectMinorVersion = 1;

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

enum class ConnectState : uint8_t {
    Disconnected,   // nothing running
    Starting,       // components initialising
    Connected,      // DNS resolver + proxy active
    Stopping,       // components shutting down
    Error,          // unrecoverable error
};

// Connect mode: how traffic is routed.
enum class ConnectMode : uint8_t {
    Socks5,         // local SOCKS5 proxy (default)
    Tun,            // TUN interface (future)
};

// Routing policy for DNS and traffic.
enum class RoutingPolicy : uint8_t {
    LunOnly,        // only .lune traffic through resolver/proxy
    AllTraffic,     // all traffic through the proxy (VPN mode)
    Selective,      // selected apps/CIDRs only
};

// ---------------------------------------------------------------------------
// ConnectConfig — populated from TOML or defaults
// ---------------------------------------------------------------------------

struct ConnectConfig {
    // --- Network ---
    uint16_t dns_port = 5335;                // local DNS stub listen port
    uint16_t socks_port = 1080;              // SOCKS5 proxy listen port
    std::string listen_address = "127.0.0.1";

    // --- DNS ---
    std::string upstream_dns = "1.1.1.1:53"; // fallback for non-.lune queries
    std::vector<std::string> lune_upstreams;  // upstream resolvers for .lune
    uint32_t dns_cache_max = 4096;

    // --- Routing ---
    ConnectMode mode = ConnectMode::Socks5;
    RoutingPolicy routing = RoutingPolicy::LunOnly;
    bool kill_switch = false;                 // block non-.lune when connected

    // --- Proxy ---
    std::string proxy_username;
    std::string proxy_password;
    uint32_t connect_timeout_ms = 10000;
    size_t max_connections = 0;               // 0 = unlimited

    // --- P2P / Astrolune network ---
    std::vector<std::string> seed_peers;      // initial peer addresses
    std::string chain_id;                     // network chain ID
    std::string data_dir;                     // persistent state directory

    // --- Logging ---
    bool log_dns = false;
    bool log_proxy = false;

    // --- Paths ---
    std::filesystem::path config_path;        // resolved config file path
};

// ---------------------------------------------------------------------------
// ConnectError — non-exception error type
// ---------------------------------------------------------------------------

enum class ConnectErrorCode {
    ConfigFileNotFound,
    ConfigParseFailed,
    ConfigInvalidField,
    DnsStartFailed,
    DnsStopFailed,
    DnsResolveFailed,
    ProxyStartFailed,
    ProxyStopFailed,
    TunNotSupported,
    AlreadyRunning,
    NotRunning,
    AlreadyStopping,
    StateTransitionInvalid,
    IoError,
    InternalError,
};

struct ConnectError {
    ConnectErrorCode code = ConnectErrorCode::InternalError;
    std::string message;

    static ConnectError make(ConnectErrorCode c, std::string msg) {
        return ConnectError{c, std::move(msg)};
    }
};

// ---------------------------------------------------------------------------
// DnsResolveResult — result of a single DNS resolution
// ---------------------------------------------------------------------------

struct DnsResolveResult {
    std::string name;
    std::vector<uint8_t> rdata;
    uint16_t rrtype = 1;      // A record by default
    uint32_t ttl = 0;
};

// ---------------------------------------------------------------------------
// ConnectStatus — snapshot returned by status()
// ---------------------------------------------------------------------------

struct ConnectStatus {
    ConnectState state = ConnectState::Disconnected;
    ConnectMode mode = ConnectMode::Socks5;
    RoutingPolicy routing = RoutingPolicy::LunOnly;
    bool kill_switch = false;

    uint16_t dns_port = 0;
    uint16_t socks_port = 0;

    size_t active_connections = 0;
    size_t dns_cache_entries = 0;

    uint64_t total_resolved = 0;
    uint64_t total_connections = 0;
};

// ---------------------------------------------------------------------------
// AstroluneConnect — the main client
// ---------------------------------------------------------------------------

class AstroluneConnect {
public:
    AstroluneConnect();
    ~AstroluneConnect();

    AstroluneConnect(const AstroluneConnect&) = delete;
    AstroluneConnect& operator=(const AstroluneConnect&) = delete;
    AstroluneConnect(AstroluneConnect&&) noexcept;
    AstroluneConnect& operator=(AstroluneConnect&&) noexcept;

    // --- Lifecycle --------------------------------------------------------

    // Load configuration from file and apply defaults.
    std::expected<void, ConnectError> load_config(
        const std::filesystem::path& path);

    // Start DNS resolver and proxy.  Applies configuration.
    std::expected<void, ConnectError> start();

    // Stop all components gracefully.
    std::expected<void, ConnectError> stop();

    // Transition to stopped state from Error (if possible).
    std::expected<void, ConnectError> reset();

    // --- Status -----------------------------------------------------------

    ConnectStatus status() const;

    // Current state.
    ConnectState state() const;

    // --- DNS resolution (one-shot) ----------------------------------------

    // Resolve a single name through the local resolver (with upstream query
    // and caching).  Useful for CLI `resolve` command.
    std::expected<std::vector<DnsResolveResult>, ConnectError>
    resolve(std::string_view name);

    // --- Configuration (after construction, before start) -----------------

    void set_config(ConnectConfig config);
    const ConnectConfig& config() const;

    // --- CLI commands (return exit codes) ---------------------------------

    // Print current status to stdout.
    int cmd_status() const;

    // Print configuration to stdout.
    int cmd_config() const;

    // Resolve a name and print results.
    int cmd_resolve(std::string_view name);

    // --- Signal handling --------------------------------------------------

    // Install a signal handler that calls stop() on SIGINT/SIGTERM.
    // Returns false if installation failed.
    bool install_signal_handler();

    // --- Static helpers ---------------------------------------------------

    // Default config file path: ~/.config/astrolune/connect.toml
    static std::filesystem::path default_config_path();

    // Print usage/help to stdout.
    static void print_help();

    // Print version to stdout.
    static void print_version();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------------------
// TOML config parser (minimal, no external dependencies)
// ---------------------------------------------------------------------------

// Parse a TOML file into ConnectConfig.  Returns an error if the file
// cannot be read or contains invalid fields.
std::expected<ConnectConfig, ConnectError> parse_toml_config(
    const std::filesystem::path& path);

// Serialize a ConnectConfig to TOML text (for `config --dump`).
std::string serialize_toml_config(const ConnectConfig& cfg);

}  // namespace astrolune::connect

#endif  // ASTROLUNE_CONNECT_ASTROLUNE_CONNECT_HPP
