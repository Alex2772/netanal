#pragma once

#include <chrono>
#include <cstddef>
#include <span>
#include <variant>

#include <AUI/Common/AOptional.h>
#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>
#include <AUI/Traits/strings.h>

namespace net {

using namespace std::chrono_literals;
using Ms = std::chrono::duration<double, std::milli>;

struct Failure {
    AString error;
};

/// getaddrinfo, both families, sorted and unique. Blocking, no timeout of its own.
std::variant<AVector<AString>, Failure> resolveAll(AStringView host);

/// First IPv4 of `host` (or `host` itself if it is an IPv4 literal).
std::variant<AString, Failure> resolveIpv4(AStringView host);

struct TcpConnected {
    Ms rtt;
    /// Address the OS picked for the outgoing connection.
    AString localIp;
};

/// TCP connect to `host` (name or literal) with a timeout; closes right away.
std::variant<TcpConnected, Failure> tcpConnect(AStringView host, uint16_t port, std::chrono::milliseconds timeout);

struct UdpReply {
    AVector<std::byte> data;
    Ms rtt;
};

/// Sends one datagram to an IPv4 address and waits for one reply.
std::variant<UdpReply, Failure> udpExchange(AStringView ip, uint16_t port, std::span<const std::byte> payload,
                                            std::chrono::milliseconds timeout);

}   // namespace net
