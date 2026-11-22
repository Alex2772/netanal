#include "Online.h"

#include <future>
#include <mutex>
#include <thread>

#include <AUI/Common/AMap.h>

#include "System.h"

namespace net {

namespace {

using Clock = std::chrono::steady_clock;

constexpr auto MONITOR_URLS = std::to_array<AStringView>({
    "https://api.ipify.org?format=json",
    "https://www.cloudflare.com/cdn-cgi/trace",
});

/// Runs `work` over `items` on `workers` threads. Items not started yet are skipped once `stop` is set.
template <typename Item, typename F>
void parallelFor(std::span<const Item> items, size_t workers, const std::atomic_bool& stop, F&& work) {
    std::atomic_size_t next = 0;
    AVector<std::jthread> threads;
    for (size_t i = 0; i < std::min(workers, items.size()); ++i) {
        threads << std::jthread([&] {
            for (size_t index; !stop && (index = next++) < items.size();) {
                work(items[index]);
            }
        });
    }
}

struct SiteTask {
    Zone zone;
    Site site;
};

PerZone<ZoneIp> detectIps() {
    const auto ips = getZoneIps();
    ASet<AString> unique;
    for (const auto& ip : ips) {
        if (ip) {
            unique << *ip;
        }
    }
    AMap<AString, std::future<AOptional<Geo>>> geo;
    for (const auto& ip : unique) {
        geo[ip] = std::async(std::launch::async, [ip] { return getIpGeo(ip); });
    }
    const auto egress = detectEgress(tunnelInterfaceIps(readNetworkState().adapters));
    PerZone<ZoneIp> result;
    for (auto zone : ZONES) {
        result[zone].ip = ips[zone];
        result[zone].egress = egress[zone];
    }
    for (auto& [ip, future] : geo) {
        const auto g = future.get();
        for (auto& z : result) {
            if (z.ip == ip) {
                z.geo = g;
            }
        }
    }
    return result;
}

}   // namespace

void runOnline(const SiteLists& sites, const std::function<void(OnlineEvent)>& onEvent, const std::atomic_bool& stop) {
    std::mutex emitMutex;
    auto post = [&](OnlineEvent e) {
        std::unique_lock lock(emitMutex);
        onEvent(std::move(e));
    };

    AVector<SiteTask> siteTasks;
    for (auto zone : ZONES) {
        for (const auto& site : sites[zone]) {
            siteTasks << SiteTask { zone, site };
        }
    }
    // 3-4 parallel requests: no burst that would trigger the VPN / DNS / CDN
    parallelFor<SiteTask>(siteTasks, 4, stop, [&](const SiteTask& t) {
        // blocked sites often hang until the timeout: cut it shorter
        const auto timeout = t.zone == Zone::BLOCKED ? 2s : 5s;
        post(online::SiteChecked { runSiteTest(t.zone, t.site, timeout) });
    });

    parallelFor<NamedServer>(DNS_SERVERS, 3, stop, [&](const NamedServer& s) {
        post(online::DnsServerChecked { .label = AString(s.name),
                                        .server = AString(s.address),
                                        .result = dnsUdpQuery(s.address, "example.com") });
    });

    if (!stop) {
        if (auto gateway = defaultGateway(readNetworkState())) {
            post(online::GatewayChecked { .gateway = *gateway, .result = pingTest(*gateway) });
        }
    }

    // external IPs + speed + UDP quality per zone, in parallel
    using Extra = std::function<void()>;
    AVector<Extra> extras;
    for (auto zone : ZONES) {
        extras << Extra([&, zone] {
            const auto urls = speedEndpoints(zone);
            post(online::SpeedMeasured { zone, speedTest(urls) });
        });
    }
    extras << Extra([&] { post(online::IpsDetected { detectIps() }); });
    for (auto zone : ZONES) {
        if (!udpTargets(zone).empty()) {
            extras << Extra([&, zone] { post(online::UdpChecked { zone, udpZoneTest(zone) }); });
        }
    }
    parallelFor<Extra>(extras, 4, stop, [](const Extra& f) { f(); });

    post(online::Done {});
}

MonitorResult monitorProbe() {
    const auto network = readNetworkState();
    const auto capture = tunnelTrafficFraction(network.routes, tunnelInterfaceIps(network.adapters));
    if (capture.fraction < 0.5) {
        return { .state = MonitorState::OFF, .detail = "VPN выключен" };
    }
    MonitorResult result { .state = MonitorState::OK, .checks = { { "VPN", "активен", Severity::OK } } };

    // end-to-end HTTPS through the current path (TUN/proxy), without the system proxy
    bool ok = false;
    double ms = 0;
    for (auto url : MONITOR_URLS) {
        const auto start = Clock::now();
        ok = std::holds_alternative<HttpAnswered>(httpTest(url, false, 8s));
        ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        if (ok) {
            break;
        }
    }
    if (!ok) {
        result.checks << MonitorCheck { "Трафик", "нет ответа", Severity::BAD };
        result.state = MonitorState::SUSPECT;
        result.detail = "трафик через туннель не проходит";
        return result;
    }
    const auto severity = ms < 4000 ? Severity::OK : ms < 8000 ? Severity::WARN : Severity::BAD;
    const auto rounded = int(std::lround(ms));
    result.checks << MonitorCheck { "Трафик", "{} мс"_format(rounded), severity };
    if (severity == Severity::BAD) {
        result.state = MonitorState::SUSPECT;
        result.detail = "трафик очень медленный ({} мс)"_format(rounded);
        return result;
    }
    result.detail = "трафик {} мс"_format(rounded);
    return result;
}

}   // namespace net
