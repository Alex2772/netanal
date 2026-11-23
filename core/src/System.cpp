#include "System.h"

#include <algorithm>

#include "Match.h"

namespace net {

namespace {

AString describeDefaults(std::span<const Route> defaults) {
    AString result;
    for (const auto& r : defaults) {
        if (!result.empty()) {
            result += "; ";
        }
        result += "{} -> {} (метрика {})"_format(r.gateway, r.iface, r.metric);
    }
    return result;
}

bool viaTunnel(const Route& r) { return isOnLink(r) || isTunnelIp(r.iface); }

void analyzeRoutes(const SystemSnapshot& s, AVector<Finding>& out) {
    const auto defaults = defaultRoutes(s.network.routes);
    if (defaults.empty()) {
        return;
    }
    const auto& best = defaults.first();
    const auto desc = describeDefaults(defaults);
    const bool bestViaTunnel = viaTunnel(best);
    const bool anyViaTunnel = std::ranges::any_of(defaults, viaTunnel);
    if (defaults.size() > 1 && anyViaTunnel && bestViaTunnel) {
        out << Finding {
            .level = Level::ERR,
            .message =
                "Маршрут по умолчанию уходит в туннель: {} -> {} (метрика {}) — приоритетнее физического "
                "шлюза. ВЕСЬ трафик идёт через VPN-туннель, даже если VPN «отключён». Все шлюзы: {}"_format(
                    best.gateway, best.iface, best.metric, desc)
        };
        return;
    }
    if (defaults.size() > 1) {
        out << Finding {
            .level = Level::WARN,
            .message =
                "Несколько маршрутов по умолчанию: {}. Проверь метрики — трафик может уходить не туда."_format(desc)
        };
        return;
    }
    if (bestViaTunnel) {
        out << Finding {
            .level = Level::WARN,
            .message =
                "Единственный маршрут по умолчанию идёт через туннель ({}). Без поднятого "
                "туннеля интернет не заработает."_format(best.iface)
        };
    }
}

void analyzeAdapters(const SystemSnapshot& s, AVector<Finding>& out) {
    for (const auto& a : s.network.adapters) {
        if (isTunnelAdapter(a)) {
            out << Finding {
                .level = Level::WARN,
                .message =
                    "Найден виртуальный/туннельный адаптер «{}» ({}). Остаточные "
                    "TUN/TAP/WireGuard-адаптеры часто ломают маршрутизацию."_format(a.name, a.desc)
            };
        } else if (isVmAdapter(a)) {
            out << Finding {
                .level = Level::INFO,
                .message = "Адаптер виртуальной машины «{}» ({}) — обычно безвреден."_format(a.name, a.desc)
            };
        }
        if (a.unknown) {
            out << Finding {
                .level = Level::INFO,
                .message =
                    "Адаптер «{}» помечен как «неизвестный» — обычно это "
                    "скрытый/остаточный драйвер."_format(a.name)
            };
        }
        for (const auto& dns : a.dns) {
            const auto d = AString(AString(dns.substr(0, dns.find('('))).trim());
            if (isTunnelIp(d) || d.startsWith("10.") || d.startsWith("127.")) {
                out << Finding {
                    .level = Level::WARN,
                    .message =
                        "DNS на адаптере «{}» указывает на туннельный/локальный резолвер {}. "
                        "Если туннель выключен — DNS перестанет работать."_format(a.name, d)
                };
            }
        }
    }
}

void analyzeProxy(const SystemSnapshot& s, AVector<Finding>& out) {
    if (s.proxy.enabled) {
        const auto& server = s.proxy.server;
        if (server.contains("127.0.0.1") || server.contains("localhost")) {
            out << Finding {
                .level = Level::WARN,
                .message =
                    "Системный прокси включён и указывает на локальный порт: {}. Если "
                    "прокси-клиент выключен — приложения останутся без интернета."_format(server)
            };
        } else {
            out << Finding { .level = Level::WARN, .message = "Системный прокси включён: {}"_format(server) };
        }
    }
    if (!s.proxy.pacUrl.empty()) {
        out << Finding { .level = Level::INFO, .message = "Настроен PAC-скрипт: {}"_format(s.proxy.pacUrl) };
    }
}

size_t suspiciousRecords(const dns_cache::Records& records) {
    return std::ranges::count_if(records, [](const CacheRecord& r) {
        return std::ranges::any_of(r.ips, [](const AString& ip) { return isSuspiciousCacheIp(ip); });
    });
}

void analyzeDnsCache(const SystemSnapshot& s, AVector<Finding>& out) {
    const auto* records = std::get_if<dns_cache::Records>(&s.dnsCache);
    if (!records || records->empty()) {
        return;
    }
    if (auto sus = suspiciousRecords(*records)) {
        out << Finding {
            .level = Level::WARN,
            .message =
                "В DNS-кэше {} записей разрешаются в подозрительные адреса (loopback/частные). "
                "Очистка кэша заставит переразрешить имена."_format(sus)
        };
        return;
    }
    out << Finding {
        .level = Level::INFO, .message = "DNS-кэш: {} записей, подозрительных не найдено."_format(records->size())
    };
}

void analyzeWinsock(const SystemSnapshot& s, AVector<Finding>& out) {
    const auto base = baseLsp(s.winsock);
    if (auto third = thirdPartyLsp(s.winsock); !third.empty()) {
        out << Finding {
            .level = Level::WARN,
            .message =
                "Winsock: обнаружено {} сторонних LSP-провайдера (не Microsoft). netsh winsock reset вернёт каталог к "
                "стандартному (нужна перезагрузка)."_format(third.size()),
        };
        return;
    }
    if (!base.empty()) {
        out << Finding {
            .level = Level::INFO,
            .message = "Winsock: каталог стандартный ({} базовых провайдеров), сторонних LSP нет."_format(base.size()),
        };
    }
}

Verdict cacheVerdict(const DnsCache& cache) {
    return match(
        cache,
        [](dns_cache::NeedsAdmin) { return Verdict { .value = "нужны права админа", .severity = Severity::NEUTRAL }; },
        [](dns_cache::Unavailable) { return Verdict { .value = "н/д", .severity = Severity::NEUTRAL }; },
        [](const dns_cache::Records& records) {
            if (auto sus = suspiciousRecords(records)) {
                return Verdict { .value = "{} подозр."_format(sus), .severity = Severity::WARN };
            }
            return Verdict { .value = "Чистый", .severity = Severity::OK };
        });
}

}   // namespace

TunnelState tunnelState(const NetworkState& network) {
    TunnelState state;
    for (const auto& a : network.adapters) {
        if (!isTunnelAdapter(a)) {
            continue;
        }
        state.tunnelAdapters << a;
        if (!a.ipv4.empty()) {
            state.activeTunnels << a;
        }
    }
    const auto tunnelIps = tunnelInterfaceIps(network.adapters);
    state.capture = tunnelTrafficFraction(network.routes, tunnelIps);
    state.defaultThroughTunnel = std::ranges::any_of(
        network.routes, [&](const Route& r) { return isDefaultRoute(r) && routeThroughTunnel(r, tunnelIps); });
    return state;
}

AVector<WinsockProvider> baseLsp(std::span<const WinsockProvider> providers) {
    AVector<WinsockProvider> result;
    std::ranges::copy_if(providers, std::back_inserter(result), [](const WinsockProvider& p) {
        const auto type = p.type.lowercase();
        return type.contains("базовый") || type.contains("base");
    });
    return result;
}

AVector<WinsockProvider> thirdPartyLsp(std::span<const WinsockProvider> providers) {
    AVector<WinsockProvider> result;
    std::ranges::copy_if(baseLsp(providers), std::back_inserter(result), [](const WinsockProvider& p) {
        return !p.path.empty() && !p.path.lowercase().contains("system32");
    });
    return result;
}

AOptional<AString> defaultGateway(const NetworkState& state) {
    const auto tunnelIps = tunnelInterfaceIps(state.adapters);
    AOptional<AString> tunnelGateway;
    for (const auto& r : defaultRoutes(state.routes)) {
        if (isOnLink(r)) {
            continue;
        }
        if (!routeThroughTunnel(r, tunnelIps)) {
            return r.gateway;
        }
        if (!tunnelGateway) {
            tunnelGateway = r.gateway;
        }
    }
    return tunnelGateway;
}

PathDns pathDnsServers(std::span<const Adapter> adapters) {
    PathDns result;
    for (const auto& a : adapters) {
        auto& target = isTunnelAdapter(a) ? result.tunnel : result.direct;
        for (const auto& dns : a.dns) {
            auto d = AString(dns.trim());
            if (d.contains(":") || !isIpish(d) || target.contains(d)) {
                continue;
            }
            target << std::move(d);
        }
    }
    return result;
}

AVector<Finding> analyze(const SystemSnapshot& snapshot) {
    AVector<Finding> findings;
    analyzeRoutes(snapshot, findings);
    analyzeAdapters(snapshot, findings);
    analyzeProxy(snapshot, findings);
    if (snapshot.nrptPolicies > 0) {
        findings << Finding {
            .level = Level::WARN,
            .message =
                "Обнаружены NRPT-политики разрешения имён — их оставляют VPN-клиенты, они "
                "часто ломают DNS."
        };
    }
    if (!snapshot.hostsEntries.empty()) {
        findings << Finding {
            .level = Level::INFO,
            .message =
                "В hosts есть активные записи ({} шт.) — проверь, что они намеренные "
                "(вкладка hosts)."_format(snapshot.hostsEntries.size())
        };
    }
    analyzeDnsCache(snapshot, findings);
    analyzeWinsock(snapshot, findings);
    return findings;
}

SystemStatus determineStatus(const SystemSnapshot& snapshot) {
    const auto tunnel = tunnelState(snapshot.network);
    SystemStatus status;

    const bool active = !tunnel.activeTunnels.empty();
    status.vpnActive = active && tunnel.carriesTraffic();
    if (status.vpnActive) {
        status.vpn = { .value = "Активен", .severity = Severity::OK };
    } else if (active) {
        status.vpn = { .value = "Адаптер поднят, без маршрута", .severity = Severity::WARN };
    } else if (!tunnel.tunnelAdapters.empty()) {
        status.vpn = { .value = "Выключен (остался адаптер)", .severity = Severity::WARN };
    } else {
        status.vpn = { .value = "Выключен", .severity = Severity::NEUTRAL };
    }

    if (tunnel.carriesTraffic()) {
        status.route = { .value = "Через туннель", .severity = Severity::OK };
    } else if (tunnel.capture.fraction > 0) {
        status.route = { .value = "Частично через туннель", .severity = Severity::WARN };
    } else {
        status.route = { .value = "Напрямую", .severity = Severity::NEUTRAL };
    }

    status.proxy =
        snapshot.proxy.enabled
            ? Verdict { .value = "Включён ({})"_format(snapshot.proxy.server), .severity = Severity::WARN }
            : Verdict { .value = "Выключен", .severity = Severity::NEUTRAL };

    status.cache = cacheVerdict(snapshot.dnsCache);

    if (auto third = thirdPartyLsp(snapshot.winsock); !third.empty()) {
        status.winsock = { .value = "{} сторонних"_format(third.size()), .severity = Severity::WARN };
    } else if (!baseLsp(snapshot.winsock).empty()) {
        status.winsock = { .value = "Стандартный", .severity = Severity::OK };
    } else {
        status.winsock = { .value = "н/д", .severity = Severity::NEUTRAL };
    }

    if (tunnel.tunnelAdapters.empty()) {
        status.adapters = { .value = "Нет", .severity = Severity::OK };
    } else if (auto leftover = tunnel.tunnelAdapters.size() - tunnel.activeTunnels.size()) {
        status.adapters = {
            .value = "{} шт ({} активн., {} остаточн.)"_format(
                tunnel.tunnelAdapters.size(), tunnel.activeTunnels.size(), leftover),
            .severity = Severity::WARN
        };
    } else {
        status.adapters = {
            .value = "{} шт (активные)"_format(tunnel.tunnelAdapters.size()), .severity = Severity::NEUTRAL
        };
    }
    return status;
}

}   // namespace net
