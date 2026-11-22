#pragma once

#include "Probes.h"
#include "Severity.h"
#include "System.h"

namespace net {

/// Domains blocked in Russia at the DNS level: used to detect DNS censorship.
inline constexpr auto DNS_CENSORED_DOMAINS = std::to_array<AStringView>({ "instagram.com", "facebook.com" });

/// Resolution straight through 1.1.1.1 / 8.8.8.8, past the system cache.
Verdict dnsResolutionCheck();

/// The resolver that actually answers (whoami.akamai.net / whoami.cloudflare.com).
struct Whoami {
    AString host;
    AVector<AString> ips;
};

AOptional<Whoami> dnsWhoami();

struct CensorshipCheck {
    AString domain;
    bool systemOk = false;
    AVector<AString> systemIps;
    bool dohOk = false;
    AVector<AString> dohIps;
};

/// "Блокирует (dom)" / "Подмена (dom)" / "Не фильтруется".
Verdict dnsCensorshipVerdict(std::span<const CensorshipCheck> checks);

struct DnsReport {
    Verdict direct;
    AOptional<Whoami> whoami;
    AOptional<Geo> resolverGeo;
    AVector<CensorshipCheck> checks;
    Verdict censorship;
};

/// Full DNS analysis: correctness, resolver and its country, censorship.
DnsReport dnsAnalysis();

/// "Резолвер" row: country and provider of the resolver.
Verdict resolverVerdict(const DnsReport& report);

/// Whether the direct and the VPN path use different resolvers.
Verdict splitDnsCheck(const NetworkState& network);

}   // namespace net
