#pragma once

#include <variant>

#include <AUI/Common/ASet.h>

#include "Http.h"
#include "Sites.h"
#include "Socket.h"

namespace net {

// ---- endpoints -------------------------------------------------------------------------------------------------

struct NamedServer {
    AStringView name;
    AStringView address;
};

inline constexpr auto DNS_SERVERS = std::to_array<NamedServer>({
    { "Cloudflare", "1.1.1.1" },
    { "Cloudflare-2", "1.0.0.1" },
    { "Google", "8.8.8.8" },
    { "Google-2", "8.8.4.4" },
    { "Quad9", "9.9.9.9" },
    { "Яндекс DNS", "77.88.8.8" },
});

/// Large static files without rate limits.
AVector<AStringView> speedEndpoints(Zone zone);

/// Services echoing the client IP. With split routing the RU and foreign IPs differ.
AVector<AStringView> echoServers(Zone zone);

/// Where to connect to learn the local path of a zone (direct / tunnel).
AStringView zoneProbeHost(Zone zone);

// ---- basic probes ----------------------------------------------------------------------------------------------

struct Resolved {
    AVector<AString> ips;
    Ms rtt {};
};

/// System resolver with a hard time limit (getaddrinfo has none: it runs on a detached thread).
std::variant<Resolved, Failure> resolveHost(AStringView host, std::chrono::milliseconds timeout = 10s);

/// TCP connect RTT, about one round trip: an honest "ping". `ip` skips the DNS lookup.
std::variant<Ms, Failure> tcpTest(AStringView host, uint16_t port, AOptional<AString> ip,
                                  std::chrono::milliseconds timeout);

/// One ICMP echo through the system `ping`. The RTT is empty if the reply had no time in it.
std::variant<AOptional<int>, Failure> pingTest(AStringView host, std::chrono::milliseconds timeout = 2s);

// ---- DNS -------------------------------------------------------------------------------------------------------

struct DnsAnswer {
    Ms rtt {};
    int rcode = 0;
    int answers = 0;
    AVector<AString> ips;
};

/// A raw A query straight to `server`:53, bypassing the system resolver and its cache.
std::variant<DnsAnswer, Failure> dnsUdpQuery(AStringView server, AStringView host,
                                             std::chrono::milliseconds timeout = 3s);

/// A query over DNS-over-HTTPS: encrypted, so it is a clean reference answer.
std::variant<AVector<AString>, Failure> dohQuery(AStringView domain, AStringView server = "1.1.1.1",
                                                 std::chrono::milliseconds timeout = 6s);

// ---- geo and IPs -----------------------------------------------------------------------------------------------

struct Geo {
    AString country;
    AString countryCode;
    AString city;
    AString region;
    AString asn;
    AString org;

    bool operator==(const Geo&) const = default;
};

/// Country / city / ASN of an IPv4 address (ipwho.is, then ipinfo.io).
AOptional<Geo> getIpGeo(AStringView ip, std::chrono::milliseconds timeout = 8s);

/// The IP that servers of each zone see.
PerZone<AOptional<AString>> getZoneIps(std::chrono::milliseconds timeout = 8s);

/// Local address used to reach `host`, resolved over DoH so that fake-ip DNS does not distort the path.
AOptional<AString> getLocalSourceIp(AStringView host, std::chrono::milliseconds timeout = 4s);

struct Egress {
    AString ip;
    bool viaTunnel = false;

    bool operator==(const Egress&) const = default;
};

PerZone<AOptional<Egress>> detectEgress(const ASet<AString>& tunnelIps, std::chrono::milliseconds timeout = 4s);

// ---- UDP -------------------------------------------------------------------------------------------------------

enum class UdpKind { STUN, NTP, DNS };

struct UdpTarget {
    AStringView name;
    AStringView host;
    uint16_t port;
    UdpKind kind;
};

/// STUN 3478, NTP 123, DNS 53; only the addresses differ between zones. There is no "Заблокированные" row: UDP is not
/// blocked in Russia (blocking happens on TCP/SNI) and QUIC conflicts with Xray.
std::span<const UdpTarget> udpTargets(Zone zone);

struct UdpProbeResult {
    AString name;
    AString host;
    uint16_t port = 0;
    AString ip;
    int sent = 0;
    int received = 0;
    double loss = 100;
    AOptional<double> rtt;
    AOptional<double> rttMin;
    AOptional<double> rttMax;
    AString error;
};

UdpProbeResult udpProbe(const UdpTarget& target, std::chrono::milliseconds timeout = 1500ms, int attempts = 3);

struct UdpZoneOk {
    double rtt = 0;
    double loss = 0;
    AVector<uint16_t> ports;
    AVector<UdpProbeResult> results;
};

struct UdpZoneFailed {
    AString error;
    AVector<UdpProbeResult> results;
};

using UdpZoneResult = std::variant<UdpZoneOk, UdpZoneFailed>;

UdpZoneResult udpZoneTest(Zone zone);

// ---- speed -----------------------------------------------------------------------------------------------------

struct Speed {
    double mbps = 0;
    size_t bytes = 0;
    double seconds = 0;
};

/// Several parallel TCP streams for `duration`: on a high RTT one stream badly underestimates the speed. Tries the
/// urls in turn until one gives a result.
std::variant<Speed, Failure> speedTest(std::span<const AStringView> urls, std::chrono::milliseconds duration = 5s,
                                       int workers = 4, std::chrono::milliseconds timeout = 20s);

// ---- sites -----------------------------------------------------------------------------------------------------

struct SiteResult {
    Zone zone;
    AString name;
    AString host;
    AString url;
    std::variant<Resolved, Failure> dns;
    std::variant<Ms, Failure> tcp;
    HttpResult http;
    HttpResult httpDirect;
};

/// DNS, then TCP 443 to the resolved IPv4, then HTTP through the system proxy and directly.
SiteResult runSiteTest(Zone zone, const Site& site, std::chrono::milliseconds timeout = 5s);

}   // namespace net
