// astrolune/tools/ecosystem/proxy/socks5_proxy.cpp
//
// Implementation of the SOCKS5 / HTTP CONNECT proxy.
// Thread-per-connection model: the accept loop spawns a detached
// thread for each incoming client.  The thread negotiates the
// protocol, connects to the target (optionally via an upstream
// proxy), then shuttles data bidirectionally until either side
// closes.

#include "socks5_proxy.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
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

namespace astrolune::proxy {

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

std::expected<size_t, ProxyError> read_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto got = ::recv(fd, reinterpret_cast<char*>(buf + total),
                          static_cast<int>(n - total), 0);
        if (got <= 0) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocketRecvFailed,
                got == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(got);
    }
    return total;
}

std::expected<size_t, ProxyError> write_exact(int fd, const uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        auto sent = ::send(fd, reinterpret_cast<const char*>(buf + total),
                           static_cast<int>(n - total), 0);
        if (sent <= 0) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocketSendFailed,
                sent == 0 ? "connection closed" : std::strerror(errno)));
        }
        total += static_cast<size_t>(sent);
    }
    return total;
}

std::expected<void, ProxyError> set_nonblocking(int fd) {
#ifdef _WIN32
    u_long mode = 1;
    if (::ioctlsocket(fd, FIONBIO, &mode) != 0) {
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketCreateFailed, "ioctlsocket failed"));
    }
#else
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketCreateFailed, "fcntl failed"));
    }
#endif
    return {};
}

std::expected<void, ProxyError> set_keepalive(int fd) {
    int yes = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                     reinterpret_cast<const char*>(&yes), sizeof(yes)) < 0) {
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketCreateFailed, "setsockopt SO_KEEPALIVE"));
    }
    return {};
}

// ---------------------------------------------------------------------------
// Internal connection map
// ---------------------------------------------------------------------------

struct ConnectionKey {
    uint64_t id;
    bool operator==(const ConnectionKey& o) const noexcept = default;
};

struct ConnectionKeyHash {
    size_t operator()(const ConnectionKey& k) const noexcept {
        return std::hash<uint64_t>()(k.id);
    }
};

// ---------------------------------------------------------------------------
// Socks5Proxy::Impl
// ---------------------------------------------------------------------------

struct Socks5Proxy::Impl {
    ProxyConfig cfg;
    std::atomic<bool> running{false};
    sock_t listen_fd = kInvalidSock;
    std::thread accept_thread;
    std::atomic<uint64_t> next_id{1};

    mutable std::mutex conn_mu;
    std::unordered_map<ConnectionKey, Connection, ConnectionKeyHash> conns;

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

            set_keepalive(client_fd);

            uint64_t id = next_id.fetch_add(1, std::memory_order_relaxed);
            Connection conn{};
            conn.id = id;
            conn.client_fd = client_fd;
            conn.created_at = std::chrono::steady_clock::now();
            conn.last_active = conn.created_at;

            {
                std::lock_guard lock(conn_mu);
                conns[ConnectionKey{id}] = conn;
            }

            std::thread(&Impl::handle_client, this, id, client_fd).detach();
        }
    }

    // --- Client handler ---------------------------------------------------

    void handle_client(uint64_t id, sock_t client_fd) {
        auto remove = [&](bool mark_closed = true) {
            std::lock_guard lock(conn_mu);
            if (auto it = conns.find(ConnectionKey{id}); it != conns.end()) {
                if (mark_closed) it->second.closed = true;
                conns.erase(it);
            }
        };

        // Peek at the first bytes to distinguish SOCKS5 from HTTP CONNECT.
        uint8_t peek_buf[32]{};
        auto peek_res = ::recv(client_fd, reinterpret_cast<char*>(peek_buf),
                               sizeof(peek_buf), MSG_PEEK);
        if (peek_res <= 0) {
            CLOSE_SOCKET(client_fd);
            remove();
            return;
        }

        auto is_http = is_http_connect(peek_buf, static_cast<size_t>(peek_res));

        if (is_http) {
            handle_http_connect(id, client_fd);
        } else {
            handle_socks5(id, client_fd);
        }

        CLOSE_SOCKET(client_fd);
        remove();
    }

    // --- SOCKS5 protocol --------------------------------------------------

    void handle_socks5(uint64_t id, sock_t client_fd) {
        // Greeting
        auto method_res = socks5_greeting(client_fd, cfg);
        if (!method_res) {
            CLOSE_SOCKET(client_fd);
            return;
        }

        // Auth sub-negotiation if required
        if (*method_res == AuthMethod::UsernamePass) {
            // Read username/password sub-negotiation request
            uint8_t sub_buf[512]{};
            auto sub_len = read_exact(client_fd, sub_buf, 2);
            if (!sub_len) { CLOSE_SOCKET(client_fd); return; }

            uint8_t ulen = sub_buf[1];
            auto ures = read_exact(client_fd, sub_buf + 2, ulen);
            if (!ures) { CLOSE_SOCKET(client_fd); return; }

            uint8_t plen_buf[1]{};
            auto plres = read_exact(client_fd, plen_buf, 1);
            if (!plres) { CLOSE_SOCKET(client_fd); return; }

            auto pres = read_exact(client_fd, sub_buf + 2 + ulen, plen_buf[0]);
            if (!pres) { CLOSE_SOCKET(client_fd); return; }

            std::string user(reinterpret_cast<char*>(sub_buf + 2), ulen);
            std::string pass(reinterpret_cast<char*>(sub_buf + 2 + ulen),
                             plen_buf[0]);

            if (user != cfg.auth_username || pass != cfg.auth_password) {
                uint8_t fail_reply[2] = {0x01, 0x01};
                write_exact(client_fd, fail_reply, 2);
                CLOSE_SOCKET(client_fd);
                return;
            }

            uint8_t ok_reply[2] = {0x01, 0x00};
            write_exact(client_fd, ok_reply, 2);
        }

        // CONNECT request
        auto connect_res = socks5_connect_request(client_fd);
        if (!connect_res) {
            socks5_send_reply(client_fd, 0x01);
            CLOSE_SOCKET(client_fd);
            return;
        }

        auto [host, port] = std::move(*connect_res);

        // Update connection tracking
        {
            std::lock_guard lock(conn_mu);
            if (auto it = conns.find(ConnectionKey{id}); it != conns.end()) {
                it->second.target_host = host;
                it->second.target_port = port;
            }
        }

        // Connect to target
        sock_t target_fd = kInvalidSock;
        auto connect_target = connect_to(host, port);
        if (!connect_target) {
            socks5_send_reply(client_fd, 0x05);  // connection refused
            CLOSE_SOCKET(client_fd);
            return;
        }
        target_fd = *connect_target;

        // Send success reply
        uint8_t reply[10]{};
        reply[0] = 0x05;  // version
        reply[1] = 0x00;  // success
        reply[2] = 0x00;  // reserved
        reply[3] = 0x01;  // IPv4 address type
        // BND.ADDR = 0.0.0.0, BND.PORT = 0
        write_exact(client_fd, reply, 10);

        // Bidirectional relay
        relay(client_fd, target_fd, id);

        CLOSE_SOCKET(target_fd);
    }

    // --- HTTP CONNECT protocol --------------------------------------------

    void handle_http_connect(uint64_t id, sock_t client_fd) {
        // Read the full HTTP request until \r\n\r\n
        std::string request_data;
        request_data.reserve(4096);

        char buf[4096];
        while (request_data.size() < 8192) {
            auto n = ::recv(client_fd, buf, sizeof(buf), 0);
            if (n <= 0) { CLOSE_SOCKET(client_fd); return; }
            request_data.append(buf, static_cast<size_t>(n));
            if (request_data.find("\r\n\r\n") != std::string::npos) break;
        }

        auto data = reinterpret_cast<const uint8_t*>(request_data.data());
        auto parse_res = parse_http_connect(data, request_data.size());
        if (!parse_res) {
            std::string resp =
                "HTTP/1.1 400 Bad Request\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            return;
        }

        auto [host, port] = std::move(*parse_res);

        // Update tracking
        {
            std::lock_guard lock(conn_mu);
            if (auto it = conns.find(ConnectionKey{id}); it != conns.end()) {
                it->second.target_host = host;
                it->second.target_port = port;
                it->second.authenticated = true;
            }
        }

        // Connect to target
        auto connect_target = connect_to(host, port);
        if (!connect_target) {
            std::string resp =
                "HTTP/1.1 502 Bad Gateway\r\n"
                "Connection: close\r\n\r\n";
            write_exact(client_fd,
                        reinterpret_cast<const uint8_t*>(resp.data()),
                        resp.size());
            CLOSE_SOCKET(client_fd);
            return;
        }
        sock_t target_fd = *connect_target;

        // Send 200 OK
        std::string resp =
            "HTTP/1.1 200 Connection Established\r\n"
            "Connection: close\r\n\r\n";
        write_exact(client_fd,
                    reinterpret_cast<const uint8_t*>(resp.data()),
                    resp.size());

        relay(client_fd, target_fd, id);
        CLOSE_SOCKET(target_fd);
    }

    // --- SOCKS5 greeting implementation -----------------------------------

    static std::expected<AuthMethod, ProxyError>
    socks5_greeting(int fd, const ProxyConfig& cfg) {
        // Read version + nmethods + methods
        uint8_t header[2]{};
        auto hr = read_exact(fd, header, 2);
        if (!hr) return std::unexpected(hr.error());

        if (header[0] != 0x05) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocksUnsupportedVersion,
                "unsupported SOCKS version: " + std::to_string(header[0])));
        }

        uint8_t nmethods = header[1];
        std::vector<uint8_t> methods(nmethods);
        auto mr = read_exact(fd, methods.data(), nmethods);
        if (!mr) return std::unexpected(mr.error());

        // Determine which method to use
        AuthMethod chosen = AuthMethod::NoAcceptable;

        if (cfg.auth_username.empty()) {
            // No auth required — check if client supports it
            for (uint8_t m : methods) {
                if (m == static_cast<uint8_t>(AuthMethod::NoAuth)) {
                    chosen = AuthMethod::NoAuth;
                    break;
                }
            }
        } else {
            // Username/password required
            for (uint8_t m : methods) {
                if (m == static_cast<uint8_t>(AuthMethod::UsernamePass)) {
                    chosen = AuthMethod::UsernamePass;
                    break;
                }
            }
        }

        // Send method selection
        uint8_t sel[2] = {0x05, static_cast<uint8_t>(chosen)};
        auto sr = write_exact(fd, sel, 2);
        if (!sr) return std::unexpected(sr.error());

        if (chosen == AuthMethod::NoAcceptable) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::AuthRequired,
                "no acceptable authentication method"));
        }

        return chosen;
    }

    // --- SOCKS5 CONNECT request parsing -----------------------------------

    static std::expected<std::pair<std::string, uint16_t>, ProxyError>
    socks5_connect_request(int fd) {
        // VER CMD RSV ATYP
        uint8_t hdr[4]{};
        auto hr = read_exact(fd, hdr, 4);
        if (!hr) return std::unexpected(hr.error());

        if (hdr[0] != 0x05) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocksUnsupportedVersion,
                "bad version in CONNECT request"));
        }
        if (hdr[1] != 0x01) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocksUnsupportedCommand,
                "only CONNECT (0x01) is supported"));
        }

        auto atyp = static_cast<AddressType>(hdr[3]);
        std::string host;
        uint16_t port = 0;

        switch (atyp) {
        case AddressType::IPv4: {
            uint8_t addr[4]{};
            auto ar = read_exact(fd, addr, 4);
            if (!ar) return std::unexpected(ar.error());
            char buf[INET_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET, addr, buf, sizeof(buf));
            host = buf;
            break;
        }
        case AddressType::IPv6: {
            uint8_t addr[16]{};
            auto ar = read_exact(fd, addr, 16);
            if (!ar) return std::unexpected(ar.error());
            char buf[INET6_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET6, addr, buf, sizeof(buf));
            host = buf;
            break;
        }
        case AddressType::Domain: {
            uint8_t dlen{};
            auto dr = read_exact(fd, &dlen, 1);
            if (!dr) return std::unexpected(dr.error());
            std::vector<uint8_t> domain(dlen);
            auto drr = read_exact(fd, domain.data(), dlen);
            if (!drr) return std::unexpected(drr.error());
            host.assign(reinterpret_cast<char*>(domain.data()), dlen);
            break;
        }
        default:
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocksUnsupportedAddressType,
                "unsupported address type: " + std::to_string(static_cast<int>(atyp))));
        }

        uint8_t port_buf[2]{};
        auto pr = read_exact(fd, port_buf, 2);
        if (!pr) return std::unexpected(pr.error());
        port = static_cast<uint16_t>((port_buf[0] << 8) | port_buf[1]);

        return std::pair{std::move(host), port);
    }

    // --- SOCKS5 reply -----------------------------------------------------

    static std::expected<void, ProxyError> socks5_send_reply(int fd, uint8_t status) {
        uint8_t reply[10]{};
        reply[0] = 0x05;
        reply[1] = status;
        reply[2] = 0x00;
        reply[3] = 0x01;
        return write_exact(fd, reply, 10);
    }

    // --- HTTP CONNECT detection -------------------------------------------

    static bool is_http_connect(const uint8_t* data, size_t len) {
        static const char prefix[] = "CONNECT ";
        if (len < 8) return false;
        return std::memcmp(data, prefix, 8) == 0;
    }

    // --- HTTP CONNECT parsing ---------------------------------------------

    static std::expected<std::pair<std::string, uint16_t>, ProxyError>
    parse_http_connect(const uint8_t* data, size_t len) {
        // Find the first line
        std::string_view line(reinterpret_cast<const char*>(data),
                              std::min(len, size_t(4096)));

        // Verify it starts with CONNECT
        if (!line.starts_with("CONNECT ")) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::HttpConnectMalformed,
                "not a CONNECT request"));
        }

        // Extract host:port
        auto first_space = line.find(' ');
        auto second_space = line.find(' ', first_space + 1);
        if (second_space == std::string_view::npos) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::HttpConnectMalformed,
                "malformed CONNECT line"));
        }

        auto hostport = line.substr(first_space + 1,
                                    second_space - first_space - 1);

        // Split host:port
        auto colon = hostport.rfind(':');
        if (colon == std::string_view::npos) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::HttpConnectMalformed,
                "missing port in CONNECT target"));
        }

        std::string host(hostport.substr(0, colon));
        uint16_t port = 0;
        auto port_str = hostport.substr(colon + 1);
        try {
            port = static_cast<uint16_t>(std::stoi(std::string(port_str)));
        } catch (...) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::HttpConnectMalformed,
                "invalid port number"));
        }

        return std::pair{std::move(host), port};
    }

    // --- TCP connect to target (direct or via upstream) --------------------

    std::expected<sock_t, ProxyError> connect_to(
        const std::string& host, uint16_t port)
    {
        if (cfg.upstream_proxy.empty()) {
            return connect_direct(host, port);
        }
        return connect_via_upstream(host, port);
    }

    std::expected<sock_t, ProxyError> connect_direct(
        const std::string& host, uint16_t port)
    {
        // Resolve host
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* res = nullptr;
        std::string port_str = std::to_string(port);
        int rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
        if (rc != 0 || !res) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocketConnectFailed,
                "getaddrinfo failed for " + host));
        }

        sock_t fd = kInvalidSock;
        for (addrinfo* p = res; p; p = p->ai_next) {
            fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (fd == kInvalidSock) continue;

            if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
                break;
            }
            CLOSE_SOCKET(fd);
            fd = kInvalidSock;
        }
        ::freeaddrinfo(res);

        if (fd == kInvalidSock) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::SocketConnectFailed,
                "connect failed to " + host + ":" + port_str));
        }
        return fd;
    }

    std::expected<sock_t, ProxyError> connect_via_upstream(
        const std::string& host, uint16_t port)
    {
        // Parse upstream proxy address "host:port"
        auto colon = cfg.upstream_proxy.rfind(':');
        if (colon == std::string::npos) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamConnectFailed,
                "invalid upstream proxy address"));
        }

        std::string up_host = cfg.upstream_proxy.substr(0, colon);
        uint16_t up_port = 0;
        try {
            up_port = static_cast<uint16_t>(
                std::stoi(cfg.upstream_proxy.substr(colon + 1)));
        } catch (...) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamConnectFailed,
                "invalid upstream proxy port"));
        }

        // Connect to the upstream proxy
        auto up_fd = connect_direct(up_host, up_port);
        if (!up_fd) {
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamConnectFailed,
                "failed to connect to upstream proxy"));
        }

        // Send SOCKS5 greeting to upstream
        uint8_t greeting[3] = {0x05, 0x01, 0x00};  // version, nmethods, no-auth
        auto gr = write_exact(*up_fd, greeting, 3);
        if (!gr) { CLOSE_SOCKET(*up_fd); return std::unexpected(gr.error()); }

        uint8_t sel[2]{};
        auto sr = read_exact(*up_fd, sel, 2);
        if (!sr) { CLOSE_SOCKET(*up_fd); return std::unexpected(sr.error()); }

        if (sel[0] != 0x05 || sel[1] != 0x00) {
            CLOSE_SOCKET(*up_fd);
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamHandshakeFailed,
                "upstream did not accept no-auth"));
        }

        // Build CONNECT request to upstream
        std::vector<uint8_t> req;
        req.push_back(0x05);  // version
        req.push_back(0x01);  // CONNECT
        req.push_back(0x00);  // reserved
        req.push_back(0x03);  // domain name

        uint8_t dlen = static_cast<uint8_t>(host.size());
        req.push_back(dlen);
        req.insert(req.end(), host.begin(), host.end());
        req.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
        req.push_back(static_cast<uint8_t>(port & 0xFF));

        auto rr = write_exact(*up_fd, req.data(), req.size());
        if (!rr) { CLOSE_SOCKET(*up_fd); return std::unexpected(rr.error()); }

        // Read reply (version + status + rsv + atyp + address)
        uint8_t reply_hdr[4]{};
        auto rhr = read_exact(*up_fd, reply_hdr, 4);
        if (!rhr) { CLOSE_SOCKET(*up_fd); return std::unexpected(rhr.error()); }

        if (reply_hdr[1] != 0x00) {
            CLOSE_SOCKET(*up_fd);
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamHandshakeFailed,
                "upstream CONNECT failed: status " +
                    std::to_string(reply_hdr[1])));
        }

        // Read remaining address bytes based on ATYP
        switch (static_cast<AddressType>(reply_hdr[3])) {
        case AddressType::IPv4: {
            uint8_t buf[6]{};
            auto rr2 = read_exact(*up_fd, buf, 6);
            if (!rr2) { CLOSE_SOCKET(*up_fd); return std::unexpected(rr2.error()); }
            break;
        }
        case AddressType::IPv6: {
            uint8_t buf[18]{};
            auto rr2 = read_exact(*up_fd, buf, 18);
            if (!rr2) { CLOSE_SOCKET(*up_fd); return std::unexpected(rr2.error()); }
            break;
        }
        case AddressType::Domain: {
            uint8_t dlen2{};
            auto dlr = read_exact(*up_fd, &dlen2, 1);
            if (!dlr) { CLOSE_SOCKET(*up_fd); return std::unexpected(dlr.error()); }
            std::vector<uint8_t> domain_buf(dlen2 + 2);
            auto drr = read_exact(*up_fd, domain_buf.data(), dlen2 + 2);
            if (!drr) { CLOSE_SOCKET(*up_fd); return std::unexpected(drr.error()); }
            break;
        }
        default:
            CLOSE_SOCKET(*up_fd);
            return std::unexpected(ProxyError::make(
                ProxyErrorCode::UpstreamHandshakeFailed,
                "unexpected ATYP in upstream reply"));
        }

        return *up_fd;
    }

    // --- Bidirectional relay -----------------------------------------------

    void relay(sock_t a, sock_t b, uint64_t conn_id) {
#ifdef _WIN32
        // Use select-based multiplexing on Windows
        fd_set readfds;
        uint8_t buf[kBufferSize];

        while (running.load(std::memory_order_relaxed)) {
            FD_ZERO(&readfds);
            FD_SET(a, &readfds);
            FD_SET(b, &readfds);

            timeval tv{};
            tv.tv_sec = 1;
            tv.tv_usec = 0;

            int sel = ::select(0, &readfds, nullptr, nullptr, &tv);
            if (sel <= 0) break;

            auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard lock(conn_mu);
                if (auto it = conns.find(ConnectionKey{conn_id});
                    it != conns.end()) {
                    it->second.last_active = now;
                }
            }

            if (FD_ISSET(a, &readfds)) {
                auto n = ::recv(a, reinterpret_cast<char*>(buf),
                                kBufferSize, 0);
                if (n <= 0) break;
                auto wr = write_exact(b, buf, static_cast<size_t>(n));
                if (!wr) break;
            }

            if (FD_ISSET(b, &readfds)) {
                auto n = ::recv(b, reinterpret_cast<char*>(buf),
                                kBufferSize, 0);
                if (n <= 0) break;
                auto wr = write_exact(a, buf, static_cast<size_t>(n));
                if (!wr) break;
            }
        }
#else
        // Use poll() on POSIX
        pollfd fds[2];
        fds[0].fd = a;
        fds[0].events = POLLIN;
        fds[1].fd = b;
        fds[1].events = POLLIN;

        uint8_t buf[kBufferSize];

        while (running.load(std::memory_order_relaxed)) {
            fds[0].revents = 0;
            fds[1].revents = 0;

            int pol = ::poll(fds, 2, 1000);
            if (pol <= 0) break;

            auto now = std::chrono::steady_clock::now();
            {
                std::lock_guard lock(conn_mu);
                if (auto it = conns.find(ConnectionKey{conn_id});
                    it != conns.end()) {
                    it->second.last_active = now;
                }
            }

            if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
                auto n = ::recv(a, buf, kBufferSize, 0);
                if (n <= 0) break;
                auto wr = write_exact(b, buf, static_cast<size_t>(n));
                if (!wr) break;
            }

            if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
                auto n = ::recv(b, buf, kBufferSize, 0);
                if (n <= 0) break;
                auto wr = write_exact(a, buf, static_cast<size_t>(n));
                if (!wr) break;
            }
        }
#endif
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

Socks5Proxy::Socks5Proxy()
    : impl_(std::make_unique<Impl>()) {}

Socks5Proxy::Socks5Proxy(ProxyConfig config)
    : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}

Socks5Proxy::~Socks5Proxy() {
    stop();
}

Socks5Proxy::Socks5Proxy(Socks5Proxy&&) noexcept = default;
Socks5Proxy& Socks5Proxy::operator=(Socks5Proxy&&) noexcept = default;

std::expected<void, ProxyError> Socks5Proxy::start() {
    if (impl_->running.load(std::memory_order_relaxed)) {
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::AlreadyRunning, "proxy already running"));
    }

    // Create listening socket
    impl_->listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listen_fd == kInvalidSock) {
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketCreateFailed,
            "socket() failed: " + std::string(std::strerror(errno))));
    }

    int reuse = 1;
    ::setsockopt(impl_->listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(impl_->cfg.listen_port);

    if (::bind(impl_->listen_fd, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketBindFailed,
            "bind() failed on port " +
                std::to_string(impl_->cfg.listen_port) + ": " +
                std::strerror(errno)));
    }

    if (::listen(impl_->listen_fd, 16) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::SocketListenFailed,
            "listen() failed: " + std::string(std::strerror(errno))));
    }

    impl_->running.store(true, std::memory_order_release);
    impl_->accept_thread = std::thread(&Impl::accept_loop, impl_.get());

    return {};
}

void Socks5Proxy::stop() {
    impl_->running.store(false, std::memory_order_release);

    if (impl_->listen_fd != kInvalidSock) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
    }

    if (impl_->accept_thread.joinable()) {
        impl_->accept_thread.join();
    }

    // Close all active client sockets
    std::lock_guard lock(impl_->conn_mu);
    for (auto& [key, conn] : impl_->conns) {
        if (conn.client_fd != kInvalidSock) {
            CLOSE_SOCKET(conn.client_fd);
            conn.client_fd = kInvalidSock;
        }
        if (conn.target_fd != kInvalidSock) {
            CLOSE_SOCKET(conn.target_fd);
            conn.target_fd = kInvalidSock;
        }
        conn.closed = true;
    }
    impl_->conns.clear();
}

bool Socks5Proxy::is_running() const {
    return impl_->running.load(std::memory_order_acquire);
}

void Socks5Proxy::set_config(ProxyConfig config) {
    impl_->cfg = std::move(config);
}

const ProxyConfig& Socks5Proxy::config() const {
    return impl_->cfg;
}

std::vector<Connection> Socks5Proxy::active_connections() const {
    std::lock_guard lock(impl_->conn_mu);
    std::vector<Connection> result;
    result.reserve(impl_->conns.size());
    for (const auto& [key, conn] : impl_->conns) {
        result.push_back(conn);
    }
    return result;
}

size_t Socks5Proxy::connection_count() const {
    std::lock_guard lock(impl_->conn_mu);
    return impl_->conns.size();
}

std::expected<AuthMethod, ProxyError>
Socks5Proxy::socks5_greeting(int fd, const ProxyConfig& cfg) {
    return Impl::socks5_greeting(fd, cfg);
}

std::expected<void, ProxyError>
Socks5Proxy::socks5_auth_userpass(int fd, std::string_view username,
                                  std::string_view password) {
    uint8_t sub_buf[512]{};
    auto slen = read_exact(fd, sub_buf, 2);
    if (!slen) return std::unexpected(slen.error());

    uint8_t ulen = sub_buf[1];
    auto ures = read_exact(fd, sub_buf + 2, ulen);
    if (!ures) return std::unexpected(ures.error());

    uint8_t plen_buf[1]{};
    auto plres = read_exact(fd, plen_buf, 1);
    if (!plres) return std::unexpected(plres.error());

    auto pres = read_exact(fd, sub_buf + 2 + ulen, plen_buf[0]);
    if (!pres) return std::unexpected(pres.error());

    std::string user(reinterpret_cast<char*>(sub_buf + 2), ulen);
    std::string pass(reinterpret_cast<char*>(sub_buf + 2 + ulen), plen_buf[0]);

    if (user != username || pass != password) {
        uint8_t fail_reply[2] = {0x01, 0x01};
        write_exact(fd, fail_reply, 2);
        return std::unexpected(ProxyError::make(
            ProxyErrorCode::AuthFailed, "invalid credentials"));
    }

    uint8_t ok_reply[2] = {0x01, 0x00};
    return write_exact(fd, ok_reply, 2);
}

std::expected<std::pair<std::string, uint16_t>, ProxyError>
Socks5Proxy::socks5_connect_request(int fd) {
    return Impl::socks5_connect_request(fd);
}

std::expected<void, ProxyError>
Socks5Proxy::socks5_send_reply(int fd, uint8_t status) {
    return Impl::socks5_send_reply(fd, status);
}

bool Socks5Proxy::is_http_connect(const uint8_t* data, size_t len) {
    return Impl::is_http_connect(data, len);
}

std::expected<std::pair<std::string, uint16_t>, ProxyError>
Socks5Proxy::parse_http_connect(const uint8_t* data, size_t len) {
    return Impl::parse_http_connect(data, len);
}

}  // namespace astrolune::proxy
