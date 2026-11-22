#pragma once

#include "Probes.h"
#include "Severity.h"

namespace net {

/// Whether a site counts as reachable. For RU a certificate error after a successful TCP connect is the missing
/// Ministry of Digital Development CA, not unavailability.
bool siteReachable(const SiteResult& result);

struct SpeedPending {};
using SpeedState = std::variant<SpeedPending, Speed, Failure>;

/// What the online check has learned about one zone so far.
struct ZoneStats {
    size_t total = 0;
    size_t ok = 0;
    /// TCP RTTs of the reachable sites.
    AVector<double> lats;
    AVector<double> dnsMs;
    SpeedState speed;
};

/// ДОСТУПНО at >= 80 % of the sites, НЕДОСТУПНО below 50 %, otherwise ЧАСТИЧНО.
Verdict zoneStatus(size_t ok, size_t total);

/// Quality of an active VPN by the absolute speed through the tunnel (zone "Зарубежные").
Verdict vpnQualityVerdict(const ZoneStats& foreign);

struct ZoneIp {
    AOptional<AString> ip;
    AOptional<Geo> geo;
    AOptional<Egress> egress;

    bool operator==(const ZoneIp&) const = default;
};

/// Is split tunneling working (RU directly, the rest through the tunnel).
Verdict splitTunnelingStatus(const PerZone<ZoneIp>& zones, bool vpnActive);

/// Heuristic diagnosis by zone availability; empty when everything is fine or there is no data yet.
AOptional<Verdict> vpnDiagnosis(const PerZone<ZoneStats>& zones, bool vpnActive);

/// Mean without outliers (IQR filter): drops slow SYN-ACKs, keeps the typical ping.
AOptional<double> filteredAvg(std::span<const double> values);

constexpr Severity pingSeverity(double ms) {
    return ms < 150 ? Severity::OK : ms < 350 ? Severity::WARN : Severity::BAD;
}

constexpr Severity dnsSeverity(double ms) {
    return ms < 100 ? Severity::OK : ms < 300 ? Severity::WARN : Severity::BAD;
}

constexpr Severity speedSeverity(double mbps) {
    return mbps >= 15 ? Severity::OK : mbps >= 5 ? Severity::WARN : Severity::BAD;
}

constexpr Severity udpSeverity(double rtt, double loss) {
    if (loss > 25) {
        return Severity::BAD;
    }
    return loss > 0 || rtt > 150 ? Severity::WARN : Severity::OK;
}

/// "Сайты" counters: "RU 3/25  ·  Зарубежные 0/25  ·  ...".
AString zoneCountsText(const PerZone<AVector<bool>>& cells);

}   // namespace net
