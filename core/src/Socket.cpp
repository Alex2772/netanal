#include "Socket.h"

#include <algorithm>
#include <array>
#include <cstring>

// platform/<os>/NativeSocket.h, picked by the include path
#include "NativeSocket.h"

namespace net {

namespace {

using Clock = std::chrono::steady_clock;

using namespace platform;

struct Socket {
    NativeSocket handle = NO_SOCKET;

    Socket(int family, int type) : handle(::socket(family, type, 0)) {}
    Socket(Socket&& o) noexcept : handle(std::exchange(o.handle, NO_SOCKET)) {}
    Socket(const Socket&) = delete;
    ~Socket() {
        if (handle != NO_SOCKET) {
            closeSocket(handle);
        }
    }
    explicit operator bool() const { return handle != NO_SOCKET; }
};

struct AddrInfo {
    addrinfo* list = nullptr;
    AddrInfo() = default;
    AddrInfo(const AddrInfo&) = delete;
    ~AddrInfo() {
        if (list) {
            freeaddrinfo(list);
        }
    }
};

AString addressText(const sockaddr* addr) {
    std::array<char, INET6_ADDRSTRLEN> buffer {};
    if (addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(addr)->sin_addr, buffer.data(), buffer.size());
    } else if (addr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr, buffer.data(), buffer.size());
    }
    return AString(buffer.data());
}

Ms since(Clock::time_point start) { return std::chrono::duration_cast<Ms>(Clock::now() - start); }

}   // namespace

std::variant<AVector<AString>, Failure> resolveAll(AStringView host) {
    ensureSocketsInit();
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    AddrInfo info;
    if (int rc = getaddrinfo(std::string(host).c_str(), "443", &hints, &info.list); rc != 0) {
        return Failure { resolveError(rc) };
    }
    AVector<AString> ips;
    for (auto* i = info.list; i; i = i->ai_next) {
        ips << addressText(i->ai_addr);
    }
    std::ranges::sort(ips);
    ips.erase(std::unique(ips.begin(), ips.end()), ips.end());
    return ips;
}

std::variant<AString, Failure> resolveIpv4(AStringView host) {
    ensureSocketsInit();
    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    AddrInfo info;
    if (int rc = getaddrinfo(std::string(host).c_str(), nullptr, &hints, &info.list); rc != 0 || !info.list) {
        return Failure { resolveError(rc) };
    }
    return addressText(info.list->ai_addr);
}

std::variant<TcpConnected, Failure> tcpConnect(AStringView host, uint16_t port, std::chrono::milliseconds timeout) {
    ensureSocketsInit();
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    AddrInfo info;
    if (int rc = getaddrinfo(std::string(host).c_str(), std::to_string(port).c_str(), &hints, &info.list); rc != 0) {
        return Failure { resolveError(rc) };
    }
    Failure failure { "нет адресов" };
    for (auto* i = info.list; i; i = i->ai_next) {
        Socket s(i->ai_family, SOCK_STREAM);
        if (!s) {
            failure = { lastSocketError() };
            continue;
        }
        setNonBlocking(s.handle);
        const auto start = Clock::now();
        if (::connect(s.handle, i->ai_addr, int(i->ai_addrlen)) != 0 && !connectInProgress()) {
            failure = { lastSocketError() };
            continue;
        }
        pollfd fd { .fd = s.handle, .events = POLLOUT, .revents = 0 };
        const int rc = pollOne(fd, int(timeout.count()));
        if (rc == 0) {
            failure = { "таймаут" };
            continue;
        }
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(s.handle, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &len);
        if (rc < 0 || error != 0) {
            setLastSocketError(error);
            failure = { lastSocketError() };
            continue;
        }
        const auto rtt = since(start);
        sockaddr_storage local {};
        socklen_t localLen = sizeof(local);
        getsockname(s.handle, reinterpret_cast<sockaddr*>(&local), &localLen);
        return TcpConnected { .rtt = rtt, .localIp = addressText(reinterpret_cast<sockaddr*>(&local)) };
    }
    return failure;
}

std::variant<UdpReply, Failure> udpExchange(AStringView ip, uint16_t port, std::span<const std::byte> payload,
                                            std::chrono::milliseconds timeout) {
    ensureSocketsInit();
    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, std::string(ip).c_str(), &addr.sin_addr) != 1) {
        return Failure { "неверный адрес {}"_format(ip) };
    }
    Socket s(AF_INET, SOCK_DGRAM);
    if (!s) {
        return Failure { lastSocketError() };
    }
    const auto start = Clock::now();
    if (::sendto(s.handle, reinterpret_cast<const char*>(payload.data()), int(payload.size()), 0,
                 reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        return Failure { lastSocketError() };
    }
    pollfd fd { .fd = s.handle, .events = POLLIN, .revents = 0 };
    const int rc = pollOne(fd, int(timeout.count()));
    if (rc == 0) {
        return Failure { "таймаут" };
    }
    if (rc < 0) {
        return Failure { lastSocketError() };
    }
    AVector<std::byte> buffer(4096);
    const auto n =
        ::recvfrom(s.handle, reinterpret_cast<char*>(buffer.data()), int(buffer.size()), 0, nullptr, nullptr);
    if (n < 0) {
        return Failure { lastSocketError() };
    }
    const auto rtt = since(start);
    buffer.resize(size_t(n));
    return UdpReply { .data = std::move(buffer), .rtt = rtt };
}

}   // namespace net
