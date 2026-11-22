#pragma once

#include <atomic>
#include <functional>

#include "Probes.h"
#include "Verdicts.h"

namespace net {

namespace online {

struct SiteChecked {
    SiteResult result;
};

struct DnsServerChecked {
    AString label;
    AString server;
    std::variant<DnsAnswer, Failure> result;
};

struct GatewayChecked {
    AString gateway;
    std::variant<AOptional<int>, Failure> result;
};

struct SpeedMeasured {
    Zone zone;
    std::variant<Speed, Failure> result;
};

struct IpsDetected {
    PerZone<ZoneIp> zones;
};

struct UdpChecked {
    Zone zone;
    UdpZoneResult result;
};

struct Done {};

}   // namespace online

using OnlineEvent = std::variant<online::SiteChecked, online::DnsServerChecked, online::GatewayChecked,
                                 online::SpeedMeasured, online::IpsDetected, online::UdpChecked, online::Done>;

/// The online check of the original: sites of every zone (4 at a time), the DNS servers, the gateway, then speed,
/// external IPs and UDP in parallel. `onEvent` is called from worker threads, one call at a time; the last event is
/// always online::Done. Returns early once `stop` is set.
void runOnline(const SiteLists& sites, const std::function<void(OnlineEvent)>& onEvent, const std::atomic_bool& stop);

// ---- background tunnel monitor ---------------------------------------------------------------------------------

enum class MonitorState { OFF, OK, SUSPECT, BAD };

struct MonitorCheck {
    AString label;
    AString value;
    Severity severity;

    bool operator==(const MonitorCheck&) const = default;
};

struct MonitorResult {
    MonitorState state = MonitorState::OFF;
    AVector<MonitorCheck> checks;
    AString detail;

    bool operator==(const MonitorResult&) const = default;
};

/// Light tunnel check without a speed test: real end-to-end HTTPS through the current path.
MonitorResult monitorProbe();

constexpr AStringView monitorStateName(MonitorState state) {
    switch (state) {
        case MonitorState::OFF:
            return "off";
        case MonitorState::OK:
            return "ok";
        case MonitorState::SUSPECT:
            return "suspect";
        case MonitorState::BAD:
            return "bad";
    }
    return {};
}

}   // namespace net
