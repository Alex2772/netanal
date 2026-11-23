#include "Verdicts.h"

#include <algorithm>
#include <numeric>

#include "Match.h"

namespace net {

namespace {

bool answered(const HttpResult& r) { return std::holds_alternative<HttpAnswered>(r); }

bool sslError(const HttpResult& r) {
    auto* failed = std::get_if<HttpFailed>(&r);
    return failed && failed->sslError;
}

double mean(std::span<const double> values) {
    return std::accumulate(values.begin(), values.end(), 0.0) / double(values.size());
}

AOptional<double> ratio(const ZoneStats& s) {
    if (s.total == 0) {
        return std::nullopt;
    }
    return double(s.ok) / double(s.total);
}

}   // namespace

bool siteReachable(const SiteResult& result) {
    if (answered(result.http) || answered(result.httpDirect)) {
        return true;
    }
    const bool tcpOk = std::holds_alternative<Ms>(result.tcp);
    return result.zone == Zone::RU && tcpOk && (sslError(result.http) || sslError(result.httpDirect));
}

Verdict zoneStatus(size_t ok, size_t total) {
    if (total == 0) {
        return { .value = "—", .severity = Severity::NEUTRAL };
    }
    const double r = double(ok) / double(total);
    if (r >= 0.8) {
        return { .value = "ДОСТУПНО", .severity = Severity::OK };
    }
    if (r < 0.5) {
        return { .value = "НЕДОСТУПНО", .severity = Severity::BAD };
    }
    return { .value = "ЧАСТИЧНО", .severity = Severity::WARN };
}

Verdict vpnQualityVerdict(const ZoneStats& foreign) {
    AString latency;
    if (!foreign.lats.empty()) {
        auto sorted = foreign.lats;
        std::ranges::sort(sorted);
        if (const auto median = int(sorted[sorted.size() / 2])) {
            latency = " · {} мс"_format(median);
        }
    }
    return match(
        foreign.speed,
        [](SpeedPending) -> Verdict { return { .value = "проверяется…", .severity = Severity::NEUTRAL }; },
        [](const Failure&) -> Verdict {
            return { .value = "Туннель не пропускает трафик", .severity = Severity::BAD };
        },
        [&](const Speed& s) -> Verdict {
            const auto base = "{:.1f} Мбит/с{}"_format(s.mbps, latency);
            if (s.mbps < 1.0) {
                return { .value = "Критически низкая скорость ({})"_format(base), .severity = Severity::BAD };
            }
            if (s.mbps < 5.0) {
                return { .value = "Сильно режется ({})"_format(base), .severity = Severity::BAD };
            }
            if (s.mbps < 15) {
                return { .value = "Медленно ({})"_format(base), .severity = Severity::WARN };
            }
            return { .value = "В порядке ({})"_format(base), .severity = Severity::OK };
        });
}

Verdict splitTunnelingStatus(const PerZone<ZoneIp>& zones, bool vpnActive) {
    if (!vpnActive) {
        return { .value = "VPN выключен", .severity = Severity::NEUTRAL };
    }
    const auto& ru = zones[Zone::RU];
    const auto& foreign = zones[Zone::FOREIGN];
    if (ru.ip && foreign.ip && *ru.ip != *foreign.ip) {
        return { .value = "Активен (RU -> {}, зарубеж -> {})"_format(*ru.ip, *foreign.ip), .severity = Severity::OK };
    }
    // fallback: the local path, for WireGuard/AmneziaWG where routing is IP-level
    if (ru.egress && foreign.egress && !ru.egress->viaTunnel && foreign.egress->viaTunnel) {
        return { .value = "Активен (RU напрямую)", .severity = Severity::OK };
    }
    // only the blocked resources go through the tunnel (geosite/geoip ru-blocked rules)
    const auto& blocked = zones[Zone::BLOCKED];
    if (ru.ip && blocked.ip && *ru.ip != *blocked.ip) {
        return { .value = "Активен (только заблокированные -> {})"_format(*blocked.ip), .severity = Severity::OK };
    }
    if (foreign.ip && ru.ip == foreign.ip) {
        return { .value = "Нет (полный туннель)", .severity = Severity::NEUTRAL };
    }
    return { .value = "не определён", .severity = Severity::NEUTRAL };
}

AOptional<Verdict> vpnDiagnosis(const PerZone<ZoneStats>& zones, bool vpnActive) {
    const auto ru = ratio(zones[Zone::RU]);
    const auto fo = ratio(zones[Zone::FOREIGN]);
    const auto bl = ratio(zones[Zone::BLOCKED]);
    if (!ru || !fo || !bl) {
        return std::nullopt;   // no data yet
    }
    constexpr double HALF = 0.5;
    if (!vpnActive) {
        if (*bl < HALF) {
            return Verdict {
                .value = "VPN выключен (заблокированные недоступны — это ожидаемо)", .severity = Severity::NEUTRAL
            };
        }
        return std::nullopt;
    }
    if (*ru < HALF && *fo < HALF) {
        return Verdict {
            .value =
                "VPN откис: туннель поднят, но ни RU, ни обычные зарубежные не открываются — меняй "
                "локацию/провайдера",
            .severity = Severity::BAD
        };
    }
    if (*ru < HALF) {
        return Verdict {
            .value = "Проблема split-tunneling: зарубежные и заблокированные работают, а RU не идёт напрямую",
            .severity = Severity::BAD
        };
    }
    if (*fo < HALF) {
        return Verdict {
            .value = "VPN не пропускает обычные зарубежные — меняй локацию/провайдера", .severity = Severity::BAD
        };
    }
    if (*bl < HALF) {
        return Verdict {
            .value = "VPN не обходит блокировки: RU и зарубежные в норме, а заблокированные не открываются",
            .severity = Severity::BAD
        };
    }
    return std::nullopt;
}

AOptional<double> filteredAvg(std::span<const double> values) {
    if (values.empty()) {
        return std::nullopt;
    }
    if (values.size() < 4) {
        return mean(values);
    }
    AVector<double> sorted(values.begin(), values.end());
    std::ranges::sort(sorted);
    const auto n = sorted.size();
    const double q1 = sorted[n / 4];
    const double q3 = sorted[3 * n / 4];
    const double iqr = q3 - q1;
    AVector<double> kept;
    std::ranges::copy_if(values, std::back_inserter(kept),
                         [&](double v) { return q1 - 1.5 * iqr <= v && v <= q3 + 1.5 * iqr; });
    return kept.empty() ? mean(values) : mean(kept);
}

AString zoneCountsText(const PerZone<AVector<bool>>& cells) {
    AString text;
    for (auto zone : ZONES) {
        const auto& c = cells[zone];
        if (!text.empty()) {
            text += "  ·  ";
        }
        text += "{} {}/{}"_format(zoneName(zone), std::ranges::count(c, true), c.size());
    }
    return text;
}

}   // namespace net
