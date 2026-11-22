#pragma once

#include <variant>

#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>

#include "Parsers.h"
#include "Severity.h"

namespace net {

struct Table {
    AString name;
    AVector<AString> columns;
    AVector<AVector<AString>> rows;
};

/// One page of the "Система" tab.
struct Section {
    AString title;
    AVector<Table> tables;
    AString text;
};

/// Adapters and IPv4 routes: enough to tell whether traffic goes into a tunnel.
struct NetworkState {
    AVector<Adapter> adapters;
    AVector<Route> routes;
    /// Raw `ipconfig /all` / `ip addr` and `route print` / `ip route` output.
    AString adaptersText;
    AString routesText;
};

/// Reads adapters and routes from the OS. Cheap enough for the 60 s monitor.
NetworkState readNetworkState();

/// Physical default gateway (not a tunnel's on-link route).
AOptional<AString> defaultGateway(const NetworkState& state);

/// DNS servers of the direct and of the tunnel path, from adapter settings.
struct PathDns {
    AVector<AString> direct;
    AVector<AString> tunnel;
};
PathDns pathDnsServers(std::span<const Adapter> adapters);

namespace dns_cache {
struct NeedsAdmin {};
struct Unavailable {};
using Records = AVector<CacheRecord>;
}   // namespace dns_cache
using DnsCache = std::variant<dns_cache::NeedsAdmin, dns_cache::Unavailable, dns_cache::Records>;

struct SystemProxy {
    bool enabled = false;
    AString server;
    AString pacUrl;
};

struct SystemSnapshot {
    NetworkState network;
    SystemProxy proxy;
    size_t nrptPolicies = 0;
    AVector<AString> hostsEntries;
    DnsCache dnsCache = dns_cache::Unavailable {};
    /// Winsock catalog; empty off Windows.
    AVector<WinsockProvider> winsock;
    AVector<Section> sections;
};

/// Collects every section. Slow (tens of seconds on Windows): run off the UI thread.
SystemSnapshot collectSystem();

/// Heuristics over the snapshot: what looks broken after VPN tools.
AVector<Finding> analyze(const SystemSnapshot& snapshot);

/// Short verdicts for the dashboard cards.
struct SystemStatus {
    Verdict vpn;
    Verdict route;
    Verdict proxy;
    Verdict cache;
    Verdict winsock;
    Verdict adapters;
    /// The tunnel is up and carries traffic ("Активен").
    bool vpnActive = false;
};

SystemStatus determineStatus(const SystemSnapshot& snapshot);

/// Whether traffic goes into a tunnel; shared by determineStatus and the monitor.
struct TunnelState {
    AVector<Adapter> tunnelAdapters;
    AVector<Adapter> activeTunnels;
    TunnelCapture capture;
    bool defaultThroughTunnel = false;

    [[nodiscard]] bool carriesTraffic() const { return capture.fraction >= 0.5 || defaultThroughTunnel; }
};

TunnelState tunnelState(const NetworkState& network);

/// Third-party (non-system32) base Winsock providers.
AVector<WinsockProvider> thirdPartyLsp(std::span<const WinsockProvider> providers);
AVector<WinsockProvider> baseLsp(std::span<const WinsockProvider> providers);

}   // namespace net
