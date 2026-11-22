#include <future>
#include <regex>

#include <AUI/Json/AJson.h>

#include "Http.h"
#include "ProbeUtil.h"
#include "Probes.h"
#include "Socket.h"

namespace net {

using namespace detail;

AOptional<Geo> getIpGeo(AStringView ip, std::chrono::milliseconds timeout) {
    if (ip.empty() || ip.contains(':')) {
        return std::nullopt;
    }
    if (auto body = httpGet("https://ipwho.is/{}"_format(ip), timeout); auto* text = std::get_if<AString>(&body)) {
        try {
            const auto data = AJson::fromString(*text);
            const bool failed = data.asObject().contains("success") && data["success"].isBool() &&
                                !data["success"].asBool();
            if (!failed) {
                const AJson connection =
                    data.asObject().contains("connection") ? data["connection"] : AJson(AJson::Object {});
                auto asn = jsonText(connection, "asn");
                if (asn.empty()) {
                    asn = jsonText(data, "asn");
                }
                if (!asn.empty() && !asn.startsWith("AS")) {
                    asn = "AS" + asn;
                }
                auto org = jsonText(connection, "org");
                return Geo {
                    .country = jsonText(data, "country"),
                    .countryCode = jsonText(data, "country_code"),
                    .city = jsonText(data, "city"),
                    .region = jsonText(data, "region"),
                    .asn = asn,
                    .org = org.empty() ? jsonText(data, "org") : org,
                };
            }
        } catch (...) {
        }
    }
    const auto body = httpGet("https://ipinfo.io/{}/json"_format(ip), timeout);
    if (auto text = std::get_if<AString>(&body)) {
        try {
            const auto data = AJson::fromString(*text);
            if (data.asObject().contains("country")) {
                const auto org = jsonText(data, "org");
                return Geo {
                    .country = jsonText(data, "country"),
                    .countryCode = jsonText(data, "country"),
                    .city = jsonText(data, "city"),
                    .region = jsonText(data, "region"),
                    .asn = org.startsWith("AS") ? AString(org.split(' ').first()) : AString {},
                    .org = org,
                };
            }
        } catch (...) {
        }
    }
    return std::nullopt;
}

PerZone<AOptional<AString>> getZoneIps(std::chrono::milliseconds timeout) {
    struct Task {
        Zone zone;
        AStringView url;
        std::future<AOptional<AString>> ip;
    };
    AVector<Task> tasks;
    for (auto zone : ZONES) {
        for (auto url : echoServers(zone)) {
            tasks << Task { zone, url, std::async(std::launch::async, [url, timeout]() -> AOptional<AString> {
                               auto body = httpGet(url, timeout, 12000);
                               auto* text = std::get_if<AString>(&body);
                               if (!text) {
                                   return std::nullopt;
                               }
                               std::string candidate = AString(text->trim(" \t\r\n")).toStdString();
                               if (url.ends_with("/cdn-cgi/trace")) {
                                   static const std::regex TRACE_IP(R"((?:^|\n)ip=([^\n]+))");
                                   if (std::smatch m; std::regex_search(candidate, m, TRACE_IP)) {
                                       candidate = m[1].str();
                                   }
                               }
                               if (url.ends_with("format=json")) {
                                   try {
                                       candidate = jsonText(AJson::fromString(candidate), "ip").toStdString();
                                   } catch (...) {
                                   }
                               }
                               static const std::regex V4(R"((?:\d{1,3}\.){3}\d{1,3})");
                               static const std::regex V6(R"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})");
                               std::smatch m;
                               if (std::regex_search(candidate, m, V4) || std::regex_search(candidate, m, V6)) {
                                   return AString(m[0].str());
                               }
                               return std::nullopt;
                           }) };
        }
    }
    PerZone<AOptional<AString>> result;
    for (auto& task : tasks) {
        auto ip = task.ip.get();
        if (ip && !result[task.zone]) {
            result[task.zone] = std::move(ip);
        }
    }
    return result;
}

AOptional<AString> getLocalSourceIp(AStringView host, std::chrono::milliseconds timeout) {
    AVector<AString> targets;
    if (auto doh = dohQuery(host); auto* ips = std::get_if<AVector<AString>>(&doh)) {
        targets = *ips;
    }
    targets << AString(host);   // fallback to the system resolver
    for (const auto& target : targets) {
        if (auto c = tcpConnect(target, 443, timeout); auto* connected = std::get_if<TcpConnected>(&c)) {
            return connected->localIp;
        }
    }
    return std::nullopt;
}

PerZone<AOptional<Egress>> detectEgress(const ASet<AString>& tunnelIps, std::chrono::milliseconds timeout) {
    PerZone<AOptional<Egress>> result;
    for (auto zone : ZONES) {
        if (auto src = getLocalSourceIp(zoneProbeHost(zone), timeout)) {
            result[zone] = Egress { .ip = *src, .viaTunnel = tunnelIps.contains(*src) };
        }
    }
    return result;
}

}   // namespace net
