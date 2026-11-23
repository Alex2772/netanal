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
  { .id = Sid::VPN, .label = "VPN/туннель", .row = "Туннель" },
  { .id = Sid::ROUTE, .label = "Маршрутизация", .row = "Режим" },
  { .id = Sid::PROXY, .label = "Системный прокси", .row = "Прокси" },
  { .id = Sid::CACHE, .label = "DNS-кэш", .row = "Кэш" },
  { .id = Sid::WINSOCK, .label = "Winsock (LSP)", .row = "" },
  { .id = Sid::ADAPTERS, .label = "Вирт. адаптеры", .row = "Адаптеры" },
  { .id = Sid::DNS_LIVE, .label = "DNS (напрямую)", .row = "Резолвинг" },
  { .id = Sid::RESOLVER, .label = "DNS-резолвер", .row = "Резолвер" },
  { .id = Sid::SPLIT_DNS, .label = "Split DNS", .row = "Split DNS" },
  { .id = Sid::CENSORSHIP, .label = "DNS-фильтрация", .row = "Фильтрация" },
  { .id = Sid::VPN_QUALITY, .label = "VPN-качество", .row = "Качество" },
  { .id = Sid::SPLIT, .label = "Split-tunneling", .row = "Split" },
  { .id = Sid::DIAGNOSIS, .label = "Диагноз VPN", .row = "Диагноз" },
});
static_assert(STATUS_SPECS.size() == size_t(Sid::COUNT));

constexpr const StatusSpec& spec(Sid id) { return STATUS_SPECS[size_t(id)]; }

/// Zones of the "UDP (игры)" card: UDP is not checked for the blocked one.
inline constexpr auto UDP_ZONES = std::to_array({ net::Zone::RU, net::Zone::FOREIGN });

inline const net::Verdict PENDING = { .value = "…" };

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
