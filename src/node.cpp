#include "ecosystem/proxy/socks5_proxy.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_running{true};

void handle_signal(int) {
    g_running.store(false);
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program
              << " [--port 1080] [--upstream host:port]\n";
}

}  // namespace

int main(int argc, char** argv) {
    astrolune::proxy::ProxyConfig config;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            config.listen_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if (arg == "--upstream" && i + 1 < argc) {
            config.upstream_proxy = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 2;
        }
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    astrolune::proxy::Socks5Proxy node(config);
    auto started = node.start();
    if (!started) {
        std::cerr << "Failed to start proxy node: "
                  << started.error().message << "\n";
        return 1;
    }

    std::cout << "Astrolune proxy node listening on TCP "
              << config.listen_port << "\n";
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    node.stop();
    std::cout << "Astrolune proxy node stopped\n";
    return 0;
}
