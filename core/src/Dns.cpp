#include "Dns.h"

#include <algorithm>

namespace net {

namespace {

bool anySuspicious(std::span<const AString> ips) {
    return std::ranges::any_of(ips, [](const AString& ip) { return isSuspiciousCacheIp(ip); });
}

/// IP of the resolver behind one of `servers`, asked directly over UDP.
AOptional<AString> resolverIp(std::span<const AString> servers) {
    for (const auto& server : servers) {
        auto answer = dnsUdpQuery(server, "whoami.akamai.net");
        if (auto* a = std::get_if<DnsAnswer>(&answer); a && !a->ips.empty()) {
            return a->ips.first();
        }
    }
    return std::nullopt;
}

bool isRussia(AStringView country) { return AString(country).lowercase().startsWith("russ"); }

}   // namespace

Verdict dnsResolutionCheck() {
    enum class Outcome { OK, POISON, FAIL };
    AVector<Outcome> outcomes;
    for (AStringView server : { AStringView("1.1.1.1"), AStringView("8.8.8.8") }) {
        auto answer = dnsUdpQuery(server, "example.com", 3s);
        auto* a = std::get_if<DnsAnswer>(&answer);
        if (!a) {
            outcomes << Outcome::FAIL;
        } else if (!a->ips.empty() && !anySuspicious(a->ips)) {
            outcomes << Outcome::OK;
        } else {
            outcomes << Outcome::POISON;
        }
    }
    if (outcomes.contains(Outcome::OK)) {
        return { .value = "Корректен", .severity = Severity::OK };
    }
    if (outcomes.contains(Outcome::POISON)) {
        return { .value = "Подменяется", .severity = Severity::BAD };
    }
    return { .value = "Блокируется (UDP/53)", .severity = Severity::BAD };
}

AOptional<Whoami> dnsWhoami() {
    for (AStringView name : { AStringView("whoami.akamai.net"), AStringView("whoami.cloudflare.com") }) {
        auto r = resolveHost(name);
        if (auto* resolved = std::get_if<Resolved>(&r); resolved && !resolved->ips.empty()) {
            return Whoami { .host = AString(name), .ips = resolved->ips };
        }
    }
    return std::nullopt;
}

Verdict dnsCensorshipVerdict(std::span<const CensorshipCheck> checks) {
    for (const auto& c : checks) {
        // the system does not resolve, DoH does: the domain is blocked at DNS
        if (!c.systemOk && c.dohOk && !c.dohIps.empty()) {
            return { .value = "Блокирует ({})"_format(c.domain), .severity = Severity::BAD };
        }
        // the system returned 0.0.0.0 / private / loopback: spoofing
        if (c.systemOk && anySuspicious(c.systemIps)) {
            return { .value = "Подмена ({})"_format(c.domain), .severity = Severity::BAD };
        }
    }
    return { .value = "Не фильтруется", .severity = Severity::OK };
}

DnsReport dnsAnalysis() {
    DnsReport report;
    report.direct = dnsResolutionCheck();
    report.whoami = dnsWhoami();
    if (report.whoami && !report.whoami->ips.empty()) {
        report.resolverGeo = getIpGeo(report.whoami->ips.first());
    }
    for (auto domain : DNS_CENSORED_DOMAINS) {
        CensorshipCheck check { .domain = AString(domain) };
        if (auto system = resolveHost(domain); auto* r = std::get_if<Resolved>(&system)) {
            check.systemOk = true;
            check.systemIps = r->ips;
        }
        if (auto doh = dohQuery(domain); auto* ips = std::get_if<AVector<AString>>(&doh)) {
            check.dohOk = true;
            check.dohIps = *ips;
        }
        report.checks << std::move(check);
    }
    report.censorship = dnsCensorshipVerdict(report.checks);
    return report;
}

Verdict resolverVerdict(const DnsReport& report) {
    if (report.resolverGeo && !report.resolverGeo->country.empty()) {
        const auto provider = report.resolverGeo->org.split(' ').first();
        return { .value = "{} · {}"_format(report.resolverGeo->country, provider), .severity = Severity::OK };
    }
    if (report.whoami) {
        return { .value = "определён (без гео)", .severity = Severity::NEUTRAL };
    }
    return { .value = "не определён", .severity = Severity::NEUTRAL };
}

Verdict splitDnsCheck(const NetworkState& network) {
    const auto [direct, tunnel] = pathDnsServers(network.adapters);
    if (tunnel.empty()) {
        return { .value = "не настроен (один DNS)", .severity = Severity::NEUTRAL };
    }
    if (ASet<AString>(tunnel.begin(), tunnel.end()) == ASet<AString>(direct.begin(), direct.end())) {
        return { .value = "не настроен (общий DNS)", .severity = Severity::NEUTRAL };
    }
    const auto directIp = resolverIp(direct);
    const auto tunnelIp = resolverIp(tunnel);
    if (directIp && tunnelIp && *directIp != *tunnelIp) {
        const auto directGeo = getIpGeo(*directIp);
        const auto tunnelGeo = getIpGeo(*tunnelIp);
        const auto dc = directGeo ? directGeo->country : AString {};
        const auto tc = tunnelGeo ? tunnelGeo->country : AString {};
        if (!dc.empty() && !tc.empty()) {
            const bool ok = isRussia(dc) && !isRussia(tc);
            return {
                .value = "активен: прямой → {}, VPN → {}"_format(dc, tc), .severity = ok ? Severity::OK : Severity::WARN
            };
        }
        return { .value = "активен (прямой {}, VPN {})"_format(*directIp, *tunnelIp), .severity = Severity::OK };
    }
    if (directIp && tunnelIp) {
        return { .value = "оба пути через один резолвер", .severity = Severity::WARN };
    }
    if (directIp) {
        return { .value = "VPN DNS не отвечает", .severity = Severity::BAD };
    }
    if (tunnelIp) {
        return { .value = "прямой DNS не отвечает", .severity = Severity::BAD };
    }
    return { .value = "DNS не отвечает", .severity = Severity::BAD };
}

}   // namespace net
