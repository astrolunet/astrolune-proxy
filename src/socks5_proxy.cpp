// SOCKS5 / HTTP CONNECT proxy for Astrolune.

#include "socks5_proxy.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  using sock_t = SOCKET;
  constexpr sock_t kInvalidSock = INVALID_SOCKET;
  #define CLOSE_SOCKET closesocket
  using ssize_t = ptrdiff_t;
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
    if (::ioctlsocket(fd, FIONBIO, &mode) != 0)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketCreateFailed, "ioctlsocket"));
#else
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketCreateFailed, "fcntl"));
#endif
    return {};
}

std::expected<void, ProxyError> set_keepalive(int fd) {
    int yes = 1;
    if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
                     reinterpret_cast<const char*>(&yes), sizeof(yes)) < 0)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketCreateFailed, "setsockopt"));
    return {};
}

// ---------------------------------------------------------------------------
// Internal types
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

    void accept_loop();
    void handle_client(uint64_t id, sock_t client_fd);
    void handle_socks5(uint64_t id, sock_t client_fd);
    void handle_http_connect(uint64_t id, sock_t client_fd);
    std::expected<void, ProxyError> connect_and_relay(sock_t client_fd,
                                                       const std::string& host,
                                                       uint16_t port);
    void relay(sock_t a, sock_t b);
};

void Socks5Proxy::Impl::accept_loop() {
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
        { std::lock_guard lock(conn_mu); conns[ConnectionKey{id}] = conn; }
        std::thread(&Impl::handle_client, this, id, client_fd).detach();
    }
}

void Socks5Proxy::Impl::handle_client(uint64_t id, sock_t client_fd) {
    auto remove = [&](bool mark_closed = true) {
        std::lock_guard lock(conn_mu);
        if (auto it = conns.find(ConnectionKey{id}); it != conns.end()) {
            if (mark_closed) it->second.closed = true;
            conns.erase(it);
        }
    };

    uint8_t peek_buf[32]{};
    auto peek_res = ::recv(client_fd, reinterpret_cast<char*>(peek_buf),
                           sizeof(peek_buf), MSG_PEEK);
    if (peek_res <= 0) { CLOSE_SOCKET(client_fd); remove(); return; }

    if (Socks5Proxy::is_http_connect(peek_buf, static_cast<size_t>(peek_res)))
        handle_http_connect(id, client_fd);
    else
        handle_socks5(id, client_fd);

    CLOSE_SOCKET(client_fd);
    remove();
}

void Socks5Proxy::Impl::handle_socks5(uint64_t /*id*/, sock_t client_fd) {
    auto method_res = Socks5Proxy::socks5_greeting(client_fd, cfg);
    if (!method_res) { CLOSE_SOCKET(client_fd); return; }

    if (*method_res == AuthMethod::UsernamePass) {
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
        std::string pass(reinterpret_cast<char*>(sub_buf + 2 + ulen), plen_buf[0]);
        if (user != cfg.auth_username || pass != cfg.auth_password) {
            uint8_t fail[2] = {0x01, 0x01};
            write_exact(client_fd, fail, 2);
            CLOSE_SOCKET(client_fd);
            return;
        }
        uint8_t ok[2] = {0x01, 0x00};
        write_exact(client_fd, ok, 2);
    }

    auto req = Socks5Proxy::socks5_connect_request(client_fd);
    if (!req) { CLOSE_SOCKET(client_fd); return; }

    auto& [host, port] = *req;
    auto res = connect_and_relay(client_fd, host, port);
    if (!res) Socks5Proxy::socks5_send_reply(client_fd, 0x01);
    else Socks5Proxy::socks5_send_reply(client_fd, 0x00);
}

void Socks5Proxy::Impl::handle_http_connect(uint64_t /*id*/, sock_t client_fd) {
    uint8_t buf[4096]{};
    ssize_t total = 0;
    while (total < static_cast<ssize_t>(sizeof(buf))) {
        auto n = ::recv(client_fd, reinterpret_cast<char*>(buf + total),
                        sizeof(buf) - total, 0);
        if (n <= 0) { CLOSE_SOCKET(client_fd); return; }
        total += n;
        if (std::string_view(reinterpret_cast<char*>(buf), total).find("\r\n\r\n") !=
            std::string_view::npos)
            break;
    }

    auto req = Socks5Proxy::parse_http_connect(buf, static_cast<size_t>(total));
    if (!req) { CLOSE_SOCKET(client_fd); return; }

    auto& [host, port] = *req;
    auto res = connect_and_relay(client_fd, host, port);
    if (!res) {
        const char* fail = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        write_exact(client_fd, reinterpret_cast<const uint8_t*>(fail), strlen(fail));
    } else {
        const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
        write_exact(client_fd, reinterpret_cast<const uint8_t*>(ok), strlen(ok));
    }
}

std::expected<void, ProxyError> Socks5Proxy::Impl::connect_and_relay(
    sock_t client_fd, const std::string& host, uint16_t port) {

    sock_t target_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (target_fd == kInvalidSock)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketCreateFailed, "socket"));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        CLOSE_SOCKET(target_fd);
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketConnectFailed, "inet_pton"));
    }

    if (::connect(target_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        CLOSE_SOCKET(target_fd);
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketConnectFailed, "connect"));
    }

    relay(client_fd, target_fd);
    CLOSE_SOCKET(target_fd);
    return {};
}

void Socks5Proxy::Impl::relay(sock_t a, sock_t b) {
    uint8_t buf[kBufferSize];
    pollfd fds[2]{};
    fds[0].fd = a; fds[0].events = POLLIN;
    fds[1].fd = b; fds[1].events = POLLIN;

    while (true) {
        int ret = ::poll(fds, 2, 5000);
        if (ret <= 0) break;

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            auto n = ::recv(a, buf, kBufferSize, 0);
            if (n <= 0) break;
            if (!write_exact(b, buf, static_cast<size_t>(n))) break;
        }
        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            auto n = ::recv(b, buf, kBufferSize, 0);
            if (n <= 0) break;
            if (!write_exact(a, buf, static_cast<size_t>(n))) break;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

Socks5Proxy::Socks5Proxy() : impl_(std::make_unique<Impl>()) {}
Socks5Proxy::Socks5Proxy(ProxyConfig config) : impl_(std::make_unique<Impl>()) {
    impl_->cfg = std::move(config);
}
Socks5Proxy::~Socks5Proxy() { stop(); }
Socks5Proxy::Socks5Proxy(Socks5Proxy&&) noexcept = default;
Socks5Proxy& Socks5Proxy::operator=(Socks5Proxy&&) noexcept = default;

std::expected<void, ProxyError> Socks5Proxy::start() {
    if (impl_->running.load(std::memory_order_relaxed))
        return std::unexpected(ProxyError::make(ProxyErrorCode::AlreadyRunning, "already running"));

    impl_->listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (impl_->listen_fd == kInvalidSock)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketCreateFailed, "socket"));

    int reuse = 1;
    ::setsockopt(impl_->listen_fd, SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(impl_->cfg.listen_port);

    if (::bind(impl_->listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketBindFailed, "bind"));
    }

    if (::listen(impl_->listen_fd, 16) < 0) {
        CLOSE_SOCKET(impl_->listen_fd);
        impl_->listen_fd = kInvalidSock;
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketListenFailed, "listen"));
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
    if (impl_->accept_thread.joinable()) impl_->accept_thread.join();
    std::lock_guard lock(impl_->conn_mu);
    for (auto& [key, conn] : impl_->conns) {
        if (conn.client_fd != kInvalidSock) { CLOSE_SOCKET(conn.client_fd); conn.client_fd = kInvalidSock; }
        if (conn.target_fd != kInvalidSock) { CLOSE_SOCKET(conn.target_fd); conn.target_fd = kInvalidSock; }
        conn.closed = true;
    }
}

bool Socks5Proxy::is_running() const { return impl_->running.load(std::memory_order_relaxed); }
void Socks5Proxy::set_config(ProxyConfig config) { impl_->cfg = std::move(config); }
const ProxyConfig& Socks5Proxy::config() const { return impl_->cfg; }

std::vector<Connection> Socks5Proxy::active_connections() const {
    std::lock_guard lock(impl_->conn_mu);
    std::vector<Connection> out;
    out.reserve(impl_->conns.size());
    for (auto& [k, v] : impl_->conns) out.push_back(v);
    return out;
}

size_t Socks5Proxy::connection_count() const {
    std::lock_guard lock(impl_->conn_mu);
    return impl_->conns.size();
}

// ---------------------------------------------------------------------------
// Static protocol helpers
// ---------------------------------------------------------------------------

std::expected<AuthMethod, ProxyError> Socks5Proxy::socks5_greeting(
    int fd, const ProxyConfig& cfg) {

    uint8_t header[2]{};
    if (!read_exact(fd, header, 2))
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "read greeting"));
    if (header[0] != 0x05)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksUnsupportedVersion, "version"));

    uint8_t nmethods = header[1];
    std::vector<uint8_t> methods(nmethods);
    if (!read_exact(fd, methods.data(), nmethods))
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "read methods"));

    bool has_noauth = std::find(methods.begin(), methods.end(), 0x00) != methods.end();
    bool has_userpass = std::find(methods.begin(), methods.end(), 0x02) != methods.end();

    uint8_t chosen = 0xFF;
    if (!cfg.auth_username.empty() && has_userpass) chosen = 0x02;
    else if (has_noauth) chosen = 0x00;
    else return std::unexpected(ProxyError::make(ProxyErrorCode::AuthRequired, "no acceptable method"));

    uint8_t reply[2] = {0x05, chosen};
    if (!write_exact(fd, reply, 2))
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "write reply"));

    return static_cast<AuthMethod>(chosen);
}

std::expected<void, ProxyError> Socks5Proxy::socks5_auth_userpass(
    int fd, std::string_view username, std::string_view password) {

    uint8_t header[2]{};
    if (!read_exact(fd, header, 2))
        return std::unexpected(ProxyError::make(ProxyErrorCode::AuthFailed, "read sub-negot"));
    if (header[0] != 0x01)
        return std::unexpected(ProxyError::make(ProxyErrorCode::AuthFailed, "version"));

    uint8_t ulen = header[1];
    std::vector<uint8_t> buf(ulen + 1);
    if (!read_exact(fd, buf.data(), ulen + 1))
        return std::unexpected(ProxyError::make(ProxyErrorCode::AuthFailed, "read cred"));

    uint8_t plen = buf[ulen];
    std::string user(reinterpret_cast<char*>(buf.data()), ulen);
    std::string pass(reinterpret_cast<char*>(buf.data() + ulen + 1), plen);

    uint8_t status = (user == username && pass == password) ? 0x00 : 0x01;
    uint8_t reply[2] = {0x01, status};
    write_exact(fd, reply, 2);

    if (status != 0x00)
        return std::unexpected(ProxyError::make(ProxyErrorCode::AuthFailed, "bad credentials"));
    return {};
}

std::expected<std::pair<std::string, uint16_t>, ProxyError>
Socks5Proxy::socks5_connect_request(int fd) {
    uint8_t header[4]{};
    if (!read_exact(fd, header, 4))
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "read header"));
    if (header[0] != 0x05 || header[1] != 0x01)
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocksUnsupportedCommand, "cmd"));

    std::string host;
    uint16_t port = 0;

    switch (header[3]) {
        case 0x01: { // IPv4
            uint8_t addr[4 + 2]{};
            if (!read_exact(fd, addr, 6))
                return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "ipv4"));
            char ip[INET_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET, addr, ip, sizeof(ip));
            host = ip;
            port = ntohs(*reinterpret_cast<uint16_t*>(addr + 4));
            break;
        }
        case 0x03: { // Domain
            uint8_t dlen{};
            if (!read_exact(fd, &dlen, 1))
                return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "dlen"));
            std::vector<char> domain(dlen);
            if (!read_exact(fd, reinterpret_cast<uint8_t*>(domain.data()), dlen + 2))
                return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "domain"));
            host = std::string(domain.data(), dlen);
            port = ntohs(*reinterpret_cast<uint16_t*>(domain.data() + dlen));
            break;
        }
        case 0x04: { // IPv6
            uint8_t addr[16 + 2]{};
            if (!read_exact(fd, addr, 18))
                return std::unexpected(ProxyError::make(ProxyErrorCode::SocksHandshakeFailed, "ipv6"));
            char ip[INET6_ADDRSTRLEN]{};
            ::inet_ntop(AF_INET6, addr, ip, sizeof(ip));
            host = ip;
            port = ntohs(*reinterpret_cast<uint16_t*>(addr + 16));
            break;
        }
        default:
            return std::unexpected(ProxyError::make(ProxyErrorCode::SocksUnsupportedAddressType, "atype"));
    }

    return std::pair{std::move(host), port};
}

std::expected<void, ProxyError> Socks5Proxy::socks5_send_reply(int fd, uint8_t status) {
    uint8_t reply[10]{};
    reply[0] = 0x05; reply[1] = status; reply[2] = 0x00; reply[3] = 0x01;
    if (!write_exact(fd, reply, 10))
        return std::unexpected(ProxyError::make(ProxyErrorCode::SocketSendFailed, "write reply"));
    return {};
}

bool Socks5Proxy::is_http_connect(const uint8_t* data, size_t len) {
    if (len < 7) return false;
    return std::string_view(reinterpret_cast<const char*>(data), len).substr(0, 7) == "CONNECT";
}

std::expected<std::pair<std::string, uint16_t>, ProxyError>
Socks5Proxy::parse_http_connect(const uint8_t* data, size_t len) {
    std::string_view view(reinterpret_cast<const char*>(data), len);
    auto line_end = view.find("\r\n");
    if (line_end == std::string_view::npos)
        return std::unexpected(ProxyError::make(ProxyErrorCode::HttpConnectMalformed, "no CRLF"));

    auto line = view.substr(0, line_end);
    auto host_start = line.find(' ');
    if (host_start == std::string_view::npos)
        return std::unexpected(ProxyError::make(ProxyErrorCode::HttpConnectMalformed, "no space"));
    host_start++;

    auto colon = line.find(':', host_start);
    if (colon == std::string_view::npos)
        return std::unexpected(ProxyError::make(ProxyErrorCode::HttpConnectMalformed, "no colon"));

    std::string host(line.substr(host_start, colon - host_start));
    uint16_t port = 0;
    auto port_str = line.substr(colon + 1);
    try { port = static_cast<uint16_t>(std::stoi(std::string(port_str))); }
    catch (...) {
        return std::unexpected(ProxyError::make(ProxyErrorCode::HttpConnectMalformed, "bad port"));
    }

    return std::pair{std::move(host), port};
}

}  // namespace astrolune::proxy
