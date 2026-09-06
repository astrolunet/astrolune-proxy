#include "ecosystem/connect/astrolune_connect.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

int main() {
    using astrolune::connect::ConnectConfig;
    using astrolune::connect::ConnectErrorCode;
    using astrolune::connect::parse_toml_config;
    using astrolune::connect::RoutingPolicy;
    using astrolune::connect::serialize_toml_config;

    const auto path = std::filesystem::temp_directory_path() /
                      "astrolune-proxy-config-test.toml";
    std::error_code ec;
    std::filesystem::remove(path, ec);

    ConnectConfig config;
    config.dns_port = 5335;
    config.socks_port = 1080;
    config.listen_address = "127.0.0.1";
    config.upstream_dns = "1.1.1.1:53";
    config.dns_cache_max = 128;
    config.routing = RoutingPolicy::Selective;
    config.kill_switch = true;
    config.proxy_username = "user\"line\\next";
    config.proxy_password = "pass\x01\x7f";
    config.connect_timeout_ms = 2500;
    config.max_connections = 32;
    config.log_dns = true;
    config.log_proxy = true;

    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << serialize_toml_config(config);
    }

    const auto parsed_result = parse_toml_config(path);
    assert(parsed_result.has_value());
    const auto& parsed = *parsed_result;
    assert(parsed.dns_port == config.dns_port);
    assert(parsed.socks_port == config.socks_port);
    assert(parsed.listen_address == config.listen_address);
    assert(parsed.upstream_dns == config.upstream_dns);
    assert(parsed.dns_cache_max == config.dns_cache_max);
    assert(parsed.routing == config.routing);
    assert(parsed.kill_switch == config.kill_switch);
    assert(parsed.proxy_username == config.proxy_username);
    assert(parsed.proxy_password == config.proxy_password);
    assert(parsed.connect_timeout_ms == config.connect_timeout_ms);
    assert(parsed.max_connections == config.max_connections);
    assert(parsed.log_dns == config.log_dns);
    assert(parsed.log_proxy == config.log_proxy);
    assert(parsed.config_path == path);

    std::filesystem::remove(path, ec);

    const auto missing = parse_toml_config(path);
    assert(!missing.has_value());
    assert(missing.error().code == ConnectErrorCode::ConfigFileNotFound);

    std::cout << "proxy config tests passed\n";
    return 0;
}
