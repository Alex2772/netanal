#include "Parsers.h"

#include <algorithm>
#include <bit>
#include <regex>

#include "Shell.h"

namespace net {

namespace {

AString trimmed(AStringView s) { return AString(AString(s).trim(" \t\r\n")); }
AString trimmed(const std::string& s) { return trimmed(AStringView(s.data(), s.size())); }

bool startsWithCi(AStringView s, AStringView prefix) {
    return AString(s).lowercase().startsWith(AString(prefix).lowercase());
}

AString strip(AStringView s, AStringView prefix) { return trimmed(s.substr(prefix.size())); }

/// `value` up to the first `(` or `%`: "192.168.1.5(Основной)" -> "192.168.1.5".
AString cutAddress(AStringView value) { return trimmed(value.substr(0, value.find_first_of("(%"))); }

std::smatch search(const std::string& s, const std::regex& re) {
    std::smatch m;
    std::regex_search(s, m, re);
    return m;
}

}   // namespace

AVector<Route> parseRoutePrint(AStringView text) {
    static const std::regex ACTIVE("Активные маршруты|Active Routes");
    static const std::regex PERSISTENT("Постоянные маршруты|Persistent Routes");
    static const std::regex ROW(R"(^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$)");
    AVector<Route> routes;
    bool inActive = false;
    for (const auto& line : lines(text)) {
        const auto& s = line.toStdString();
        if (std::regex_search(s, ACTIVE)) {
            inActive = true;
            continue;
        }
        if (std::regex_search(s, PERSISTENT)) {
            inActive = false;
            continue;
        }
        if (!inActive) {
            continue;
        }
        std::smatch m;
        if (!std::regex_match(s, m, ROW)) {
            continue;
        }
        routes << Route {
            .network = m[1].str(),
            .mask = m[2].str(),
            .gateway = m[3].str(),
            .iface = m[4].str(),
            .metric = std::stoi(m[5].str()),
        };
    }
    return routes;
}

AVector<Adapter> parseIpconfigAdapters(AStringView text) {
    static constexpr auto UNKNOWN_PREFIXES = std::to_array<AStringView>({ "Неизвестный адаптер", "Unknown adapter" });
    static constexpr auto TYPE_PREFIXES = std::to_array<AStringView>({
        "Адаптер Ethernet",
        "Ethernet adapter",
        "Адаптер беспроводной локальной сети",
        "Wireless LAN adapter",
        "Адаптер туннеля",
        "Tunnel adapter",
        "Адаптер",
        "Adapter",
    });
    static const std::regex FIELD(R"(^(.+?)\s*\.+\s*:\s*(.*)$)");

    enum class Field { NONE, GATEWAY, DNS };

    AVector<Adapter> adapters;
    Field last = Field::NONE;
    for (const auto& line : lines(text)) {
        if (!line.empty() && !std::isspace(static_cast<unsigned char>(line.front())) &&
            AString(line.trimRight(" \t\r")).endsWith(":")) {
            Adapter adapter;
            adapter.rawName = trimmed(AString(line.trim(" \t\r")).trimRight(':'));
            AString name = adapter.rawName;
            for (auto prefix : UNKNOWN_PREFIXES) {
                if (startsWithCi(name, "{} "_format(prefix))) {
                    adapter.unknown = true;
                    name = strip(name, prefix);
                    break;
                }
            }
            for (auto prefix : TYPE_PREFIXES) {
                if (startsWithCi(name, "{} "_format(prefix))) {
                    name = strip(name, prefix);
                    break;
                }
            }
            adapter.name = std::move(name);
            adapters << std::move(adapter);
            last = Field::NONE;
            continue;
        }
        if (adapters.empty()) {
            continue;
        }
        auto& cur = adapters.last();
        const auto s = trimmed(line);
        std::smatch m;
        const auto& str = s.toStdString();
        if (!std::regex_match(str, m, FIELD)) {
            if (!s.empty() && last == Field::DNS && isIpish(s)) {
                cur.dns << s;
            } else if (!s.empty() && last == Field::GATEWAY) {
                cur.gateway += " " + s;
            }
            continue;
        }
        const auto key = trimmed(m[1].str()).lowercase();
        const auto value = trimmed(m[2].str());
        last = Field::NONE;
        if (key.contains("описание") || key.contains("description")) {
            cur.desc = value;
        } else if (key.contains("ipv4") && (key.contains("адрес") || key.contains("address"))) {
            cur.ipv4 = cutAddress(value);
        } else if (key.contains("шлюз") || key.contains("gateway")) {
            cur.gateway = value;
            last = Field::GATEWAY;
        } else if (key.contains("состояние среды") || key.contains("media state")) {
            cur.status = value;
        } else if (key.contains("dhcp") && (key.contains("включен") || key.contains("enabled"))) {
            cur.dhcp = value;
        } else if (key.contains("dns") && !key.contains("суффикс") && !key.contains("suffix")) {
            if (!value.empty()) {
                cur.dns << value;
            }
            last = Field::DNS;
        }
    }
    return adapters;
}

AVector<CacheRecord> parseDisplayDns(AStringView text) {
    static const std::regex VALUE(R"(:\s*(.+)$)");
    AVector<CacheRecord> records;
    for (const auto& line : lines(text)) {
        const auto s = trimmed(line);
        if (s.empty()) {
            continue;
        }
        if (s.contains("Имя записи") || s.contains("Record Name")) {
            auto m = search(s.toStdString(), VALUE);
            records << CacheRecord { .name = m.empty() ? s : trimmed(m[1].str()) };
            continue;
        }
        if (records.empty() || !(s.contains("Запись") || s.contains("Record")) || !s.contains(":")) {
            continue;
        }
        auto value = trimmed(AStringView(s).substr(s.find(':') + 1));
        if (isIpish(value)) {
            records.last().ips << std::move(value);
        }
    }
    return records;
}

AVector<WinsockProvider> parseWinsockCatalog(AStringView text) {
    static const std::regex DESC(R"(Описание\s*[:.]+\s*(.+))");
    static const std::regex PATH(R"(Путь поставщика\s*[:.]+\s*(.+))");
    static const std::regex TYPE(R"(Тип элемента\s*[:.]+\s*(.+))");
    static constexpr AStringView SEPARATOR = "Элемент поставщика";

    auto group = [](const std::string& block, const std::regex& re) -> AString {
        auto m = search(block, re);
        return m.empty() ? AString {} : trimmed(m[1].str());
    };

    AVector<WinsockProvider> providers;
    size_t pos = 0;
    while (pos <= text.size()) {
        auto next = text.find(SEPARATOR, pos);
        const auto block = std::string(text.substr(pos, next == AStringView::npos ? AStringView::npos : next - pos));
        if (auto desc = group(block, DESC); !desc.empty()) {
            providers << WinsockProvider { .type = group(block, TYPE), .desc = desc, .path = group(block, PATH) };
        }
        if (next == AStringView::npos) {
            break;
        }
        pos = next + SEPARATOR.size();
    }
    return providers;
}

bool isIpish(AStringView s) {
    return !s.empty() && std::ranges::all_of(s, [](char c) { return std::isxdigit(static_cast<unsigned char>(c)) ||
                                                                     c == '.' || c == ':' || c == '%'; });
}

AOptional<uint32_t> parseIpv4(AStringView ip) {
    uint32_t result = 0;
    int octets = 0;
    size_t pos = 0;
    while (octets < 4) {
        auto end = ip.find('.', pos);
        auto part = ip.substr(pos, end == AStringView::npos ? AStringView::npos : end - pos);
        const auto digits = std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; });
        if (part.empty() || part.size() > 3 || !digits) {
            return std::nullopt;
        }
        const auto value = std::stoi(std::string(part));
        if (value > 255) {
            return std::nullopt;
        }
        result = (result << 8) | uint32_t(value);
        ++octets;
        if (end == AStringView::npos) {
            break;
        }
        pos = end + 1;
    }
    if (octets != 4) {
        return std::nullopt;
    }
    return result;
}

bool isTunnelIp(AStringView ip) {
    struct Net {
        uint32_t base;
        int prefix;
    };
    static constexpr std::array NETS = {
        Net { .base = 0x64400000, .prefix = 10 },   // 100.64.0.0/10
        Net { .base = 0xC6120000, .prefix = 15 },   // 198.18.0.0/15
        Net { .base = 0xA9FE0000, .prefix = 16 },   // 169.254.0.0/16
    };
    auto addr = parseIpv4(ip);
    if (!addr) {
        return false;
    }
    return std::ranges::any_of(NETS, [&](const Net& n) {
        const uint32_t mask = ~uint32_t(0) << (32 - n.prefix);
        return (*addr & mask) == n.base;
    });
}

AOptional<int> maskToPrefix(AStringView mask) {
    auto value = parseIpv4(mask);
    if (!value) {
        return std::nullopt;
    }
    return std::popcount(*value);
}

bool isSuspiciousCacheIp(AStringView ip) {
    static constexpr auto PREFIXES =
        std::to_array<AStringView>({ "127.", "10.", "192.168.", "100.64.", "100.65.", "198.18.", "169.254." });
    if (ip == "0.0.0.0" || ip == "::") {
        return true;
    }
    if (std::ranges::any_of(PREFIXES, [&](AStringView p) { return ip.starts_with(p); })) {
        return true;
    }
    if (!ip.starts_with("172.")) {
        return false;
    }
    auto second = AStringView(ip.substr(4, ip.find('.', 4) - 4)).toInt();
    return second && *second >= 16 && *second <= 31;
}

bool isTunnelAdapter(const Adapter& adapter) {
    return containsAny("{} {}"_format(adapter.name, adapter.desc), VPN_ADAPTER_PATTERNS);
}

bool isVmAdapter(const Adapter& adapter) {
    return containsAny("{} {}"_format(adapter.name, adapter.desc), VM_ADAPTER_PATTERNS);
}

ASet<AString> tunnelInterfaceIps(std::span<const Adapter> adapters) {
    ASet<AString> ips;
    for (const auto& a : adapters) {
        if (isTunnelAdapter(a) && !a.ipv4.empty()) {
            ips << a.ipv4;
        }
    }
    return ips;
}

bool routeThroughTunnel(const Route& route, const ASet<AString>& tunnelIps) { return tunnelIps.contains(route.iface); }

bool isDefaultRoute(const Route& route) { return route.network == "0.0.0.0" && route.mask == "0.0.0.0"; }

bool isOnLink(const Route& route) {
    const auto gw = route.gateway.lowercase();
    return gw == "on-link" || gw == "связанный";
}

TunnelCapture tunnelTrafficFraction(std::span<const Route> routes, const ASet<AString>& tunnelIps) {
    TunnelCapture result;
    for (const auto& r : routes) {
        if (!routeThroughTunnel(r, tunnelIps)) {
            continue;
        }
        if (r.network.startsWith("224.") || r.network.startsWith("239.")) {   // multicast is not traffic
            continue;
        }
        auto prefix = maskToPrefix(r.mask);
        if (!prefix || *prefix > 8) {
            continue;
        }
        result.fraction += 1.0 / double(uint64_t(1) << *prefix);
        result.routes << r;
    }
    return result;
}

AVector<Route> defaultRoutes(std::span<const Route> routes) {
    AVector<Route> result;
    std::ranges::copy_if(routes, std::back_inserter(result), isDefaultRoute);
    std::ranges::stable_sort(result, {}, &Route::metric);
    return result;
}

}   // namespace net
