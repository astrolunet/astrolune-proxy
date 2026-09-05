// Astrolune Connect CLI implementation.
//
// Manages the lifecycle of the local DNS resolver and SOCKS5 proxy.
// Reads configuration from a TOML file.  The TOML parser is minimal
// and supports only the subset needed by ConnectConfig — no external
// TOML library dependency.

#include "ecosystem/connect/astrolune_connect.hpp"
#include "ecosystem/dns/lune_resolver.hpp"
#include "ecosystem/proxy/socks5_proxy.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

// --- Platform headers for signal handling -----------------------------------

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <signal.h>
#  include <windows.h>
#else
#  include <csignal>
#endif

namespace astrolune::connect {
namespace {

// ---------------------------------------------------------------------------
// Minimal TOML parser (subset: [section], key = "string", key = 123, etc.)
// ---------------------------------------------------------------------------

struct TomlValue {
    std::string str_val;
    int64_t int_val = 0;
    bool is_int = false;
    bool is_bool = false;
    bool bool_val = false;
};

std::string trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return std::string(s);
}

bool parse_bool(std::string_view s) {
    return s == "true" || s == "yes" || s == "1";
}

std::optional<TomlValue> parse_toml_value(std::string_view raw) {
    auto v = trim(raw);
    if (v.empty()) return std::nullopt;

    // Quoted string
    if ((v.front() == '"' && v.back() == '"') ||
        (v.front() == '\'' && v.back() == '\'')) {
        TomlValue tv;
        tv.str_val = v.substr(1, v.size() - 2);
        return tv;
    }

    // Integer
    {
        bool negative = false;
        size_t start = 0;
        if (v[0] == '-') { negative = true; start = 1; }
        bool all_digits = true;
        for (size_t i = start; i < v.size(); ++i) {
            if (v[i] < '0' || v[i] > '9') { all_digits = false; break; }
        }
        if (all_digits && start < v.size()) {
            TomlValue tv;
            tv.is_int = true;
            int64_t val = 0;
            for (size_t i = start; i < v.size(); ++i) {
                val = val * 10 + (v[i] - '0');
            }
            tv.int_val = negative ? -val : val;
            return tv;
        }
    }

    // Boolean
    if (v == "true" || v == "false" || v == "yes" || v == "no" ||
        v == "1" || v == "0") {
        TomlValue tv;
        tv.is_bool = true;
        tv.bool_val = parse_bool(v);
        return tv;
    }

    // Bare string (no quotes)
    TomlValue tv;
    tv.str_val = v;
    return tv;
}

std::unordered_map<std::string, TomlValue> parse_toml_flat(
    std::istream& stream) {

    std::unordered_map<std::string, TomlValue> result;
    std::string section;
    std::string line;

    while (std::getline(stream, line)) {
        auto trimmed = trim(std::string_view(line));
        if (trimmed.empty() || trimmed[0] == '#') continue;

        // Section header [section]
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trim(trimmed.substr(1, trimmed.size() - 2)) + ".";
            continue;
        }

        // key = value
        auto eq = trimmed.find('=');
        if (eq == std::string_view::npos) continue;

        auto key = trim(trimmed.substr(0, eq));
        auto val_raw = trimmed.substr(eq + 1);

        // Strip inline comment (only if preceded by space)
        auto hash = val_raw.find(" #");
        if (hash != std::string_view::npos) val_raw = val_raw.substr(0, hash);

        auto val = parse_toml_value(val_raw);
        if (val) {
            result[section + std::string(key)] = std::move(*val);
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// State machine helpers
// ---------------------------------------------------------------------------

bool can_start(ConnectState s) {
    return s == ConnectState::Disconnected || s == ConnectState::Error;
}

bool can_stop(ConnectState s) {
    return s == ConnectState::Connected || s == ConnectState::Starting;
}

}  // namespace

// ===========================================================================
// AstroluneConnect::Impl
// ===========================================================================

struct AstroluneConnect::Impl {
    ConnectConfig cfg;
    std::atomic<ConnectState> state{ConnectState::Disconnected};

    std::unique_ptr<dns::LuneResolver> resolver;
    std::unique_ptr<proxy::Socks5Proxy> socks_proxy;

    mutable std::mutex stats_mu;
    uint64_t total_resolved = 0;
    uint64_t total_connections = 0;

    // --- TOML config loader -----------------------------------------------

    std::expected<void, ConnectError> load_toml(const std::filesystem::path& path) {
        std::ifstream file(path);
        if (!file) {
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::ConfigFileNotFound,
                "cannot open config: " + path.string()));
        }

        auto entries = parse_toml_flat(file);

        auto get_str = [&](std::string_view key) -> std::optional<std::string> {
            auto it = entries.find(std::string(key));
            if (it == entries.end()) return std::nullopt;
            return it->second.str_val;
        };
        auto get_int = [&](std::string_view key) -> std::optional<int64_t> {
            auto it = entries.find(std::string(key));
            if (it == entries.end()) return std::nullopt;
            if (it->second.is_int) return it->second.int_val;
            try {
                return std::stoll(it->second.str_val);
            } catch (...) {
                return std::nullopt;
            }
        };
        auto get_bool = [&](std::string_view key) -> std::optional<bool> {
            auto it = entries.find(std::string(key));
            if (it == entries.end()) return std::nullopt;
            if (it->second.is_bool) return it->second.bool_val;
            return parse_bool(it->second.str_val);
        };

        // [network]
        if (auto v = get_int("network.dns_port"); v && *v > 0 && *v <= 65535)
            cfg.dns_port = static_cast<uint16_t>(*v);
        if (auto v = get_int("network.socks_port"); v && *v > 0 && *v <= 65535)
            cfg.socks_port = static_cast<uint16_t>(*v);
        if (auto v = get_str("network.listen_address"); v)
            cfg.listen_address = std::move(*v);

        // [dns]
        if (auto v = get_str("dns.upstream"); v)
            cfg.upstream_dns = std::move(*v);
        if (auto v = get_int("dns.cache_max"); v && *v > 0)
            cfg.dns_cache_max = static_cast<uint32_t>(*v);

        // [routing]
        if (auto v = get_str("routing.mode"); v) {
            if (*v == "tun") cfg.mode = ConnectMode::Tun;
            else cfg.mode = ConnectMode::Socks5;
        }
        if (auto v = get_str("routing.policy"); v) {
            if (*v == "all") cfg.routing = RoutingPolicy::AllTraffic;
            else if (*v == "selective") cfg.routing = RoutingPolicy::Selective;
            else cfg.routing = RoutingPolicy::LunOnly;
        }
        if (auto v = get_bool("routing.kill_switch"); v)
            cfg.kill_switch = *v;

        // [proxy]
        if (auto v = get_str("proxy.username"); v)
            cfg.proxy_username = std::move(*v);
        if (auto v = get_str("proxy.password"); v)
            cfg.proxy_password = std::move(*v);
        if (auto v = get_int("proxy.connect_timeout_ms"); v && *v > 0)
            cfg.connect_timeout_ms = static_cast<uint32_t>(*v);
        if (auto v = get_int("proxy.max_connections"); v && *v >= 0)
            cfg.max_connections = static_cast<size_t>(*v);

        // [network]
        if (auto v = get_str("network.chain_id"); v)
            cfg.chain_id = std::move(*v);
        if (auto v = get_str("network.data_dir"); v)
            cfg.data_dir = std::move(*v);

        // [logging]
        if (auto v = get_bool("logging.dns"); v)
            cfg.log_dns = *v;
        if (auto v = get_bool("logging.proxy"); v)
            cfg.log_proxy = *v;

        // Store the path for reference.
        cfg.config_path = path;

        return {};
    }

    // --- Component lifecycle ----------------------------------------------

    std::expected<void, ConnectError> start_components() {
        auto expected = state.load();
        if (!can_start(expected)) {
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::AlreadyRunning,
                "cannot start in current state"));
        }

        state.store(ConnectState::Starting);

        // Validate mode.
        if (cfg.mode == ConnectMode::Tun) {
            state.store(ConnectState::Error);
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::TunNotSupported,
                "TUN mode is not yet supported; use socks5"));
        }

        // --- Start DNS resolver ---
        resolver = std::make_unique<dns::LuneResolver>();
        resolver->set_port(cfg.dns_port);

        if (!cfg.upstream_dns.empty()) {
            resolver->set_default_upstream(cfg.upstream_dns);
        }

        auto dns_result = resolver->start();
        if (!dns_result) {
            state.store(ConnectState::Error);
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::DnsStartFailed,
                "DNS resolver: " + dns_result.error().message));
        }

        // --- Start SOCKS5 proxy ---
        proxy::ProxyConfig proxy_cfg;
        proxy_cfg.listen_port = cfg.socks_port;
        proxy_cfg.auth_username = cfg.proxy_username;
        proxy_cfg.auth_password = cfg.proxy_password;
        proxy_cfg.connect_timeout_ms = cfg.connect_timeout_ms;
        proxy_cfg.max_connections = cfg.max_connections;

        socks_proxy = std::make_unique<proxy::Socks5Proxy>(std::move(proxy_cfg));
        auto proxy_result = socks_proxy->start();
        if (!proxy_result) {
            resolver->stop();
            resolver.reset();
            state.store(ConnectState::Error);
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::ProxyStartFailed,
                "SOCKS5 proxy: " + proxy_result.error().message));
        }

        state.store(ConnectState::Connected);
        return {};
    }

    std::expected<void, ConnectError> stop_components() {
        auto expected = state.load();
        if (!can_stop(expected)) {
            if (expected == ConnectState::Disconnected) return {};
            return std::unexpected(ConnectError::make(
                ConnectErrorCode::NotRunning,
                "not running"));
        }

        state.store(ConnectState::Stopping);

        if (socks_proxy) {
            socks_proxy->stop();
            socks_proxy.reset();
        }
        if (resolver) {
            resolver->stop();
            resolver.reset();
        }

        state.store(ConnectState::Disconnected);
        return {};
    }
};

// ===========================================================================
// AstroluneConnect — public API
// ===========================================================================

AstroluneConnect::AstroluneConnect()
    : impl_(std::make_unique<Impl>()) {}

AstroluneConnect::~AstroluneConnect() {
    if (impl_) {
        impl_->stop_components();
    }
}

AstroluneConnect::AstroluneConnect(AstroluneConnect&&) noexcept = default;
AstroluneConnect& AstroluneConnect::operator=(AstroluneConnect&&) noexcept = default;

std::expected<void, ConnectError> AstroluneConnect::load_config(
    const std::filesystem::path& path) {
    return impl_->load_toml(path);
}

std::expected<void, ConnectError> AstroluneConnect::start() {
    return impl_->start_components();
}

std::expected<void, ConnectError> AstroluneConnect::stop() {
    return impl_->stop_components();
}

std::expected<void, ConnectError> AstroluneConnect::reset() {
    if (impl_->state.load() != ConnectState::Error) {
        return std::unexpected(ConnectError::make(
            ConnectErrorCode::StateTransitionInvalid,
            "reset only allowed from Error state"));
    }
    impl_->state.store(ConnectState::Disconnected);
    return {};
}

ConnectStatus AstroluneConnect::status() const {
    ConnectStatus s;
    s.state = impl_->state.load();
    s.mode = impl_->cfg.mode;
    s.routing = impl_->cfg.routing;
    s.kill_switch = impl_->cfg.kill_switch;
    s.dns_port = impl_->cfg.dns_port;
    s.socks_port = impl_->cfg.socks_port;

    if (impl_->socks_proxy) {
        s.active_connections = impl_->socks_proxy->connection_count();
    }
    if (impl_->resolver) {
        s.dns_cache_entries = impl_->resolver->cache().size();
    }

    std::lock_guard lock(impl_->stats_mu);
    s.total_resolved = impl_->total_resolved;
    s.total_connections = impl_->total_connections;

    return s;
}

ConnectState AstroluneConnect::state() const {
    return impl_->state.load();
}

std::expected<std::vector<DnsResolveResult>, ConnectError>
AstroluneConnect::resolve(std::string_view name) {
    if (impl_->state.load() != ConnectState::Connected) {
        return std::unexpected(ConnectError::make(
            ConnectErrorCode::NotRunning,
            "resolver not running"));
    }

    if (!impl_->resolver) {
        return std::unexpected(ConnectError::make(
            ConnectErrorCode::DnsResolveFailed,
            "no resolver instance"));
    }

    auto result = impl_->resolver->resolve(name, dns::RecordType::A);
    if (!result) {
        return std::unexpected(ConnectError::make(
            ConnectErrorCode::DnsResolveFailed,
            result.error().message));
    }

    std::vector<DnsResolveResult> out;
    out.reserve(result->size());
    for (auto& rec : *result) {
        DnsResolveResult dr;
        dr.name = std::move(rec.name);
        dr.rdata = std::move(rec.rdata);
        dr.rrtype = static_cast<uint16_t>(rec.type);
        dr.ttl = rec.ttl;
        out.push_back(std::move(dr));
    }

    {
        std::lock_guard lock(impl_->stats_mu);
        ++impl_->total_resolved;
    }

    return out;
}

void AstroluneConnect::set_config(ConnectConfig config) {
    impl_->cfg = std::move(config);
}

const ConnectConfig& AstroluneConnect::config() const {
    return impl_->cfg;
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

int AstroluneConnect::cmd_status() const {
    auto s = status();

    const char* state_str = "unknown";
    switch (s.state) {
        case ConnectState::Disconnected: state_str = "disconnected"; break;
        case ConnectState::Starting:     state_str = "starting";     break;
        case ConnectState::Connected:    state_str = "connected";    break;
        case ConnectState::Stopping:     state_str = "stopping";     break;
        case ConnectState::Error:        state_str = "error";        break;
    }

    const char* mode_str = "socks5";
    if (s.mode == ConnectMode::Tun) mode_str = "tun";

    const char* routing_str = "lune-only";
    if (s.routing == RoutingPolicy::AllTraffic) routing_str = "all";
    else if (s.routing == RoutingPolicy::Selective) routing_str = "selective";

    std::printf("state:        %s\n", state_str);
    std::printf("mode:         %s\n", mode_str);
    std::printf("routing:      %s\n", routing_str);
    std::printf("kill-switch:  %s\n", s.kill_switch ? "on" : "off");
    std::printf("dns-port:     %u\n", s.dns_port);
    std::printf("socks-port:   %u\n", s.socks_port);
    std::printf("connections:  %zu\n", s.active_connections);
    std::printf("dns-cache:    %zu\n", s.dns_cache_entries);
    std::printf("resolved:     %llu\n",
                static_cast<unsigned long long>(s.total_resolved));

    return s.state == ConnectState::Connected ? 0 : 1;
}

int AstroluneConnect::cmd_config() const {
    std::printf("dns_port             = %u\n", impl_->cfg.dns_port);
    std::printf("socks_port           = %u\n", impl_->cfg.socks_port);
    std::printf("listen_address       = \"%s\"\n",
                impl_->cfg.listen_address.c_str());
    std::printf("upstream_dns         = \"%s\"\n",
                impl_->cfg.upstream_dns.c_str());
    std::printf("dns_cache_max        = %u\n", impl_->cfg.dns_cache_max);

    const char* mode = "socks5";
    if (impl_->cfg.mode == ConnectMode::Tun) mode = "tun";
    std::printf("mode                 = \"%s\"\n", mode);

    const char* policy = "lune-only";
    if (impl_->cfg.routing == RoutingPolicy::AllTraffic) policy = "all";
    else if (impl_->cfg.routing == RoutingPolicy::Selective) policy = "selective";
    std::printf("routing              = \"%s\"\n", policy);

    std::printf("kill_switch          = %s\n",
                impl_->cfg.kill_switch ? "true" : "false");
    std::printf("connect_timeout_ms   = %u\n", impl_->cfg.connect_timeout_ms);
    std::printf("max_connections      = %zu\n", impl_->cfg.max_connections);
    std::printf("chain_id             = \"%s\"\n",
                impl_->cfg.chain_id.c_str());
    std::printf("data_dir             = \"%s\"\n",
                impl_->cfg.data_dir.string().c_str());
    std::printf("log_dns              = %s\n",
                impl_->cfg.log_dns ? "true" : "false");
    std::printf("log_proxy            = %s\n",
                impl_->cfg.log_proxy ? "true" : "false");

    if (!impl_->cfg.config_path.empty()) {
        std::printf("config_file          = \"%s\"\n",
                    impl_->cfg.config_path.string().c_str());
    }

    return 0;
}

int AstroluneConnect::cmd_resolve(std::string_view name) {
    auto result = resolve(name);
    if (!result) {
        std::fprintf(stderr, "error: %s\n", result.error().message.c_str());
        return 1;
    }

    for (const auto& dr : *result) {
        std::printf("%-30s  TTL=%-6u  type=%-5u  ",
                    dr.name.c_str(), dr.ttl, dr.rrtype);

        // Print A/AAAA rdata as human-readable IP if possible.
        if (dr.rrtype == 1 && dr.rdata.size() == 4) {
            std::printf("%u.%u.%u.%u",
                        dr.rdata[0], dr.rdata[1], dr.rdata[2], dr.rdata[3]);
        } else if (dr.rrtype == 28 && dr.rdata.size() == 16) {
            for (size_t i = 0; i < 16; i += 2) {
                if (i > 0) std::printf(":");
                std::printf("%02x%02x", dr.rdata[i], dr.rdata[i + 1]);
            }
        } else {
            std::printf("[%zu bytes]", dr.rdata.size());
        }
        std::printf("\n");
    }

    return 0;
}

// ---------------------------------------------------------------------------
// Signal handling
// ---------------------------------------------------------------------------

namespace {
    AstroluneConnect* g_instance = nullptr;
}

void signal_handler_fn(int) {
    if (g_instance) {
        g_instance->stop();
    }
}

bool AstroluneConnect::install_signal_handler() {
    g_instance = this;

#if defined(_WIN32)
    auto h = [](int) -> void { signal_handler_fn(0); };
    if (::signal(SIGINT, h) == SIG_ERR) return false;
    if (::signal(SIGTERM, h) == SIG_ERR) return false;
#else
    struct sigaction sa{};
    sa.sa_handler = signal_handler_fn;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (::sigaction(SIGINT, &sa, nullptr) != 0) return false;
    if (::sigaction(SIGTERM, &sa, nullptr) != 0) return false;
#endif

    return true;
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::filesystem::path AstroluneConnect::default_config_path() {
#if defined(_WIN32)
    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        return std::filesystem::path(appdata) / "astrolune" / "connect.toml";
    }
    return std::filesystem::path("astrolune-connect.toml");
#else
    const char* home = std::getenv("HOME");
    if (home) {
        return std::filesystem::path(home) / ".config" / "astrolune" /
               "connect.toml";
    }
    return std::filesystem::path("astrolune-connect.toml");
#endif
}

void AstroluneConnect::print_help() {
    std::printf(
        "usage: astrolune-connect <command> [options]\n"
        "\n"
        "commands:\n"
        "  start             Start DNS resolver and SOCKS5 proxy\n"
        "  stop              Stop all components\n"
        "  status            Show connection status\n"
        "  resolve <name>    Resolve a .lune domain\n"
        "  config            Show current configuration\n"
        "  config --dump     Export default configuration to stdout\n"
        "  help              Show this help\n"
        "  version           Show version\n"
        "\n"
        "options:\n"
        "  -c, --config <path>   Config file path\n"
        "                        (default: ~/.config/astrolune/connect.toml)\n"
        "\n"
        "examples:\n"
        "  astrolune-connect start\n"
        "  astrolune-connect start -c ./connect.toml\n"
        "  astrolune-connect resolve web.lune\n"
        "  astrolune-connect status\n"
        "\n"
        "configuration is read from a TOML file.  run 'config --dump' to\n"
        "see the full default configuration.\n");
}

void AstroluneConnect::print_version() {
    std::printf("astrolune-connect %d.%d\n",
                kConnectMajorVersion, kConnectMinorVersion);
}

// ===========================================================================
// TOML config parser and serializer
// ===========================================================================

std::expected<ConnectConfig, ConnectError> parse_toml_config(
    const std::filesystem::path& path) {

    ConnectConfig cfg;
    std::ifstream file(path);
    if (!file) {
        return std::unexpected(ConnectError::make(
            ConnectErrorCode::ConfigFileNotFound,
            "cannot open: " + path.string()));
    }

    auto entries = parse_toml_flat(file);

    auto get_str = [&](std::string_view key) -> std::optional<std::string> {
        auto it = entries.find(std::string(key));
        if (it == entries.end()) return std::nullopt;
        return it->second.str_val;
    };
    auto get_int = [&](std::string_view key) -> std::optional<int64_t> {
        auto it = entries.find(std::string(key));
        if (it == entries.end()) return std::nullopt;
        if (it->second.is_int) return it->second.int_val;
        try {
            return std::stoll(it->second.str_val);
        } catch (...) {
            return std::nullopt;
        }
    };
    auto get_bool = [&](std::string_view key) -> std::optional<bool> {
        auto it = entries.find(std::string(key));
        if (it == entries.end()) return std::nullopt;
        if (it->second.is_bool) return it->second.bool_val;
        return parse_bool(it->second.str_val);
    };

    // [network]
    if (auto v = get_int("network.dns_port"); v && *v > 0 && *v <= 65535)
        cfg.dns_port = static_cast<uint16_t>(*v);
    if (auto v = get_int("network.socks_port"); v && *v > 0 && *v <= 65535)
        cfg.socks_port = static_cast<uint16_t>(*v);
    if (auto v = get_str("network.listen_address"); v)
        cfg.listen_address = std::move(*v);
    if (auto v = get_str("network.chain_id"); v)
        cfg.chain_id = std::move(*v);
    if (auto v = get_str("network.data_dir"); v)
        cfg.data_dir = std::move(*v);

    // [dns]
    if (auto v = get_str("dns.upstream"); v)
        cfg.upstream_dns = std::move(*v);
    if (auto v = get_int("dns.cache_max"); v && *v > 0)
        cfg.dns_cache_max = static_cast<uint32_t>(*v);

    // [routing]
    if (auto v = get_str("routing.mode"); v) {
        if (*v == "tun") cfg.mode = ConnectMode::Tun;
        else cfg.mode = ConnectMode::Socks5;
    }
    if (auto v = get_str("routing.policy"); v) {
        if (*v == "all") cfg.routing = RoutingPolicy::AllTraffic;
        else if (*v == "selective") cfg.routing = RoutingPolicy::Selective;
        else cfg.routing = RoutingPolicy::LunOnly;
    }
    if (auto v = get_bool("routing.kill_switch"); v)
        cfg.kill_switch = *v;

    // [proxy]
    if (auto v = get_str("proxy.username"); v)
        cfg.proxy_username = std::move(*v);
    if (auto v = get_str("proxy.password"); v)
        cfg.proxy_password = std::move(*v);
    if (auto v = get_int("proxy.connect_timeout_ms"); v && *v > 0)
        cfg.connect_timeout_ms = static_cast<uint32_t>(*v);
    if (auto v = get_int("proxy.max_connections"); v && *v >= 0)
        cfg.max_connections = static_cast<size_t>(*v);

    // [logging]
    if (auto v = get_bool("logging.dns"); v)
        cfg.log_dns = *v;
    if (auto v = get_bool("logging.proxy"); v)
        cfg.log_proxy = *v;

    cfg.config_path = path;
    return cfg;
}

std::string serialize_toml_config(const ConnectConfig& cfg) {
    std::ostringstream out;

    out << "# Astrolune Connect configuration\n";
    out << "# Generated default — edit to taste.\n\n";

    out << "[network]\n";
    out << "dns_port       = " << cfg.dns_port << "\n";
    out << "socks_port     = " << cfg.socks_port << "\n";
    out << "listen_address = \"" << cfg.listen_address << "\"\n";
    out << "chain_id       = \"" << cfg.chain_id << "\"\n";
    out << "data_dir       = \"" << cfg.data_dir.string() << "\"\n\n";

    out << "[dns]\n";
    out << "upstream   = \"" << cfg.upstream_dns << "\"\n";
    out << "cache_max  = " << cfg.dns_cache_max << "\n\n";

    out << "[routing]\n";
    const char* mode = cfg.mode == ConnectMode::Tun ? "tun" : "socks5";
    const char* policy = "lune-only";
    if (cfg.routing == RoutingPolicy::AllTraffic) policy = "all";
    else if (cfg.routing == RoutingPolicy::Selective) policy = "selective";
    out << "mode        = \"" << mode << "\"\n";
    out << "policy      = \"" << policy << "\"\n";
    out << "kill_switch = " << (cfg.kill_switch ? "true" : "false") << "\n\n";

    out << "[proxy]\n";
    out << "username          = \"" << cfg.proxy_username << "\"\n";
    out << "password          = \"" << cfg.proxy_password << "\"\n";
    out << "connect_timeout_ms = " << cfg.connect_timeout_ms << "\n";
    out << "max_connections   = " << cfg.max_connections << "\n\n";

    out << "[logging]\n";
    out << "dns   = " << (cfg.log_dns ? "true" : "false") << "\n";
    out << "proxy = " << (cfg.log_proxy ? "true" : "false") << "\n";

    return out.str();
}

}  // namespace astrolune::connect
