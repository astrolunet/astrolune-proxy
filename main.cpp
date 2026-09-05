// astrolune-connect — CLI entry point.
//
//   astrolune-connect start [-c config.toml]
//   astrolune-connect stop
//   astrolune-connect status
//   astrolune-connect resolve <name>
//   astrolune-connect config [--dump]
//   astrolune-connect help
//   astrolune-connect version

#include "ecosystem/connect/astrolune_connect.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

int main(int argc, char** argv) {
    using namespace astrolune::connect;

    std::string command;
    std::string config_path_str;
    std::string resolve_name;
    bool dump_config = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) {
                config_path_str = argv[++i];
            } else {
                std::fprintf(stderr, "error: -c requires a path argument\n");
                return 2;
            }
        } else if (arg == "--dump") {
            dump_config = true;
        } else if (arg == "--help" || arg == "-h") {
            AstroluneConnect::print_help();
            return 0;
        } else if (arg == "--version" || arg == "-v") {
            AstroluneConnect::print_version();
            return 0;
        } else if (arg[0] == '-') {
            std::fprintf(stderr, "error: unknown option '%s'\n", arg.c_str());
            return 2;
        } else if (command.empty()) {
            command = arg;
        } else if (command == "resolve") {
            resolve_name = arg;
        } else {
            std::fprintf(stderr, "error: unexpected argument '%s'\n",
                         arg.c_str());
            return 2;
        }
    }

    // --- config --dump (no instance needed) ---
    if (command == "config" && dump_config) {
        ConnectConfig cfg;
        std::printf("%s", serialize_toml_config(cfg).c_str());
        return 0;
    }

    if (command.empty()) {
        AstroluneConnect::print_help();
        return 2;
    }

    if (command == "help") {
        AstroluneConnect::print_help();
        return 0;
    }

    if (command == "version") {
        AstroluneConnect::print_version();
        return 0;
    }

    // --- Build instance ---
    AstroluneConnect client;

    // Load config.
    std::filesystem::path config_path;
    if (!config_path_str.empty()) {
        config_path = config_path_str;
    } else {
        config_path = AstroluneConnect::default_config_path();
    }

    auto load_result = client.load_config(config_path);
    if (!load_result) {
        // Config file not found is non-fatal for some commands.
        if (load_result.error().code != ConnectErrorCode::ConfigFileNotFound ||
            command == "start") {
            std::fprintf(stderr, "error: %s\n",
                         load_result.error().message.c_str());
            if (command == "start") return 1;
        }
    }

    // --- Route command ---
    if (command == "start") {
        if (!client.install_signal_handler()) {
            std::fprintf(stderr, "warning: failed to install signal handler\n");
        }

        auto start_result = client.start();
        if (!start_result) {
            std::fprintf(stderr, "error: %s\n",
                         start_result.error().message.c_str());
            return 1;
        }

        std::printf("astrolune-connect: running (DNS :%u, SOCKS5 :%u)\n",
                    client.config().dns_port, client.config().socks_port);

        // Block until signal.
        // Simple busy-wait; a production version would use a condition variable.
        while (client.state() == ConnectState::Connected) {
#if defined(_WIN32)
            Sleep(500);
#else
            struct timespec ts{};
            ts.tv_sec = 0;
            ts.tv_nsec = 500'000'000;
            nanosleep(&ts, nullptr);
#endif
        }

        auto stop_result = client.stop();
        if (!stop_result) {
            std::fprintf(stderr, "warning: stop failed: %s\n",
                         stop_result.error().message.c_str());
        }

        std::printf("astrolune-connect: stopped\n");
        return 0;
    }

    if (command == "stop") {
        auto stop_result = client.stop();
        if (!stop_result) {
            std::fprintf(stderr, "error: %s\n",
                         stop_result.error().message.c_str());
            return 1;
        }
        std::printf("astrolune-connect: stopped\n");
        return 0;
    }

    if (command == "status") {
        return client.cmd_status();
    }

    if (command == "resolve") {
        if (resolve_name.empty()) {
            std::fprintf(stderr, "error: resolve requires a domain name\n");
            return 2;
        }

        // Start components for resolution.
        auto start_result = client.start();
        if (!start_result) {
            std::fprintf(stderr, "error: %s\n",
                         start_result.error().message.c_str());
            return 1;
        }

        int rc = client.cmd_resolve(resolve_name);

        client.stop();
        return rc;
    }

    if (command == "config") {
        return client.cmd_config();
    }

    std::fprintf(stderr, "error: unknown command '%s'\n", command.c_str());
    AstroluneConnect::print_help();
    return 2;
}
