#pragma once

#include <array>

#include <AUI/Common/AColor.h>

#include "MainWindow.h"
#include "Theme.h"
#include "widgets/Palette.h"

/// Tables and helpers shared by the MainWindow sources.
namespace main_window {

using widgets::rgb;

struct StatusSpec {
    Sid id;
    /// Label in the summary list.
    AStringView label;
    /// Row on a dashboard card; empty if the item has no row.
    AStringView row;
};

inline constexpr auto STATUS_SPECS = std::to_array<StatusSpec>({
    { Sid::VPN, "VPN/туннель", "Туннель" },
    { Sid::ROUTE, "Маршрутизация", "Режим" },
    { Sid::PROXY, "Системный прокси", "Прокси" },
    { Sid::CACHE, "DNS-кэш", "Кэш" },
    { Sid::WINSOCK, "Winsock (LSP)", "" },
    { Sid::ADAPTERS, "Вирт. адаптеры", "Адаптеры" },
    { Sid::DNS_LIVE, "DNS (напрямую)", "Резолвинг" },
    { Sid::RESOLVER, "DNS-резолвер", "Резолвер" },
    { Sid::SPLIT_DNS, "Split DNS", "Split DNS" },
    { Sid::CENSORSHIP, "DNS-фильтрация", "Фильтрация" },
    { Sid::VPN_QUALITY, "VPN-качество", "Качество" },
    { Sid::SPLIT, "Split-tunneling", "Split" },
    { Sid::DIAGNOSIS, "Диагноз VPN", "Диагноз" },
});
static_assert(STATUS_SPECS.size() == size_t(Sid::COUNT));

constexpr const StatusSpec& spec(Sid id) { return STATUS_SPECS[size_t(id)]; }

/// Zones of the "UDP (игры)" card: UDP is not checked for the blocked one.
inline constexpr auto UDP_ZONES = std::to_array({ net::Zone::RU, net::Zone::FOREIGN });

inline const net::Verdict PENDING = { "…" };

inline AString geoCountry(const AOptional<net::Geo>& geo) {
    if (!geo || geo->country.empty()) {
        return {};
    }
    return geo->countryCode.empty() ? geo->country : geo->countryCode;
}

inline AColor monitorColor(const AOptional<net::MonitorResult>& result) {
    if (!result) {
        return theme::MONITOR_OFF;
    }
    switch (result->state) {
        case net::MonitorState::OK:
            return theme::textColor(net::Severity::OK);
        case net::MonitorState::SUSPECT:
            return theme::textColor(net::Severity::WARN);
        case net::MonitorState::BAD:
            return theme::textColor(net::Severity::BAD);
        case net::MonitorState::OFF:
            break;
    }
    return theme::MONITOR_OFF;
}

}   // namespace main_window
