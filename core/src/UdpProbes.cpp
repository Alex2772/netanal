#include <algorithm>
#include <thread>

#include "ProbeUtil.h"
#include "Probes.h"
#include "Socket.h"

namespace net {

using namespace detail;

namespace {

AVector<std::byte> stunRequest() {
    AVector<std::byte> packet = { std::byte(0x00), std::byte(0x01), std::byte(0x00), std::byte(0x00),
                                  std::byte(0x21), std::byte(0x12), std::byte(0xA4), std::byte(0x42) };
    for (int i = 0; i < 12; ++i) {
        packet << std::byte(std::uniform_int_distribution<int>(0, 255)(rng()));
    }
    return packet;
}

AVector<std::byte> ntpRequest() {
    AVector<std::byte> packet(48, std::byte(0));
    packet[0] = std::byte(0x1B);   // client, mode 3
    return packet;
}

AVector<std::byte> payloadFor(UdpKind kind) {
    switch (kind) {
        case UdpKind::STUN:
            return stunRequest();
        case UdpKind::NTP:
            return ntpRequest();
        case UdpKind::DNS:
            return dnsQuery("example.com");
    }
    return {};
}

const PerZone<AVector<UdpTarget>> UDP_TARGETS = { {
  AVector<UdpTarget> {
    { .name = "STUN Sipnet", .host = "stun.sipnet.ru", .port = 3478, .kind = UdpKind::STUN },
    { .name = "NTP VNIIFTRI", .host = "ntp1.vniiftri.ru", .port = 123, .kind = UdpKind::NTP },
    { .name = "DNS Яндекс", .host = "77.88.8.8", .port = 53, .kind = UdpKind::DNS },
  },
  AVector<UdpTarget> {
    { .name = "STUN Cloudflare", .host = "stun.cloudflare.com", .port = 3478, .kind = UdpKind::STUN },
    { .name = "NTP Google", .host = "time.google.com", .port = 123, .kind = UdpKind::NTP },
    { .name = "DNS Cloudflare", .host = "1.1.1.1", .port = 53, .kind = UdpKind::DNS },
  },
  AVector<UdpTarget> {},
} };

}   // namespace

std::span<const UdpTarget> udpTargets(Zone zone) { return UDP_TARGETS[zone]; }

UdpProbeResult udpProbe(const UdpTarget& target, std::chrono::milliseconds timeout, int attempts) {
    UdpProbeResult r { .name = AString(target.name), .host = AString(target.host), .port = target.port };
    auto ip = resolveIpv4(target.host);
    if (auto* failure = std::get_if<Failure>(&ip)) {
        r.error = "DNS: {}"_format(failure->error);
        return r;
    }
    r.ip = std::get<AString>(ip);
    AVector<double> rtts;
    for (int i = 0; i < attempts; ++i) {
        ++r.sent;
        if (auto reply = udpExchange(r.ip, target.port, payloadFor(target.kind), timeout);
            auto* ok = std::get_if<UdpReply>(&reply)) {
            rtts << ok->rtt.count();
            ++r.received;
        }
        std::this_thread::sleep_for(50ms);
    }
    r.loss = round1(double(r.sent - r.received) * 100 / r.sent);
    if (rtts.empty()) {
        r.loss = 100;
        r.error = "нет ответа";
        return r;
    }
    double sum = 0;
    for (auto v : rtts) {
        sum += v;
    }
    r.rtt = round1(sum / double(rtts.size()));
    r.rttMin = round1(*std::ranges::min_element(rtts));
    r.rttMax = round1(*std::ranges::max_element(rtts));
    return r;
}

UdpZoneResult udpZoneTest(Zone zone) {
    const auto targets = udpTargets(zone);
    if (targets.empty()) {
        return UdpZoneFailed { .error = "нет целей" };
    }
    AVector<UdpProbeResult> results;
    for (const auto& t : targets) {
        results << udpProbe(t);
    }
    AVector<double> rtts;
    AVector<uint16_t> ports;
    int sent = 0, received = 0;
    for (const auto& r : results) {
        sent += r.sent;
        received += r.received;
        if (r.rtt) {
            rtts << *r.rtt;
            if (!ports.contains(r.port)) {
                ports << r.port;
            }
        }
    }
    if (rtts.empty()) {
        return UdpZoneFailed { .error = "UDP не отвечает", .results = std::move(results) };
    }
    std::ranges::sort(ports);
    double sum = 0;
    for (auto v : rtts) {
        sum += v;
    }
    return UdpZoneOk { .rtt = round1(sum / double(rtts.size())),
                       .loss = round1(sent ? double(sent - received) * 100 / sent : 100),
                       .ports = std::move(ports),
                       .results = std::move(results) };
}

}   // namespace net
