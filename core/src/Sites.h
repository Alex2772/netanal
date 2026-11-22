#pragma once

#include <array>

#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>
#include <AUI/IO/APath.h>

namespace net {

enum class Zone { RU, FOREIGN, BLOCKED };

inline constexpr std::array ZONES = { Zone::RU, Zone::FOREIGN, Zone::BLOCKED };

/// Zone name as the original program spells it; also the key in sites.json.
constexpr AStringView zoneName(Zone zone) {
    switch (zone) {
        case Zone::RU:
            return "RU";
        case Zone::FOREIGN:
            return "Зарубежные";
        case Zone::BLOCKED:
            return "Заблокированные";
    }
    return {};
}

/// Zone name for narrow places (a table column).
constexpr AStringView zoneShortName(Zone zone) {
    switch (zone) {
        case Zone::RU:
            return "RU";
        case Zone::FOREIGN:
            return "Заруб.";
        case Zone::BLOCKED:
            return "Забл.";
    }
    return {};
}

constexpr size_t zoneIndex(Zone zone) { return static_cast<size_t>(zone); }

/// Per-zone storage indexed by Zone.
template <typename T>
struct PerZone : std::array<T, ZONES.size()> {
    T& operator[](Zone zone) { return std::array<T, ZONES.size()>::operator[](zoneIndex(zone)); }
    const T& operator[](Zone zone) const { return std::array<T, ZONES.size()>::operator[](zoneIndex(zone)); }
};

struct Site {
    AString name;
    AString url;

    bool operator==(const Site&) const = default;
};

using SiteLists = PerZone<AVector<Site>>;

const AVector<Site>& defaultSites(Zone zone);
SiteLists defaultSiteLists();

/// "https://www.ozon.ru/x" -> "www.ozon.ru"; the url itself if it has no host.
AString hostOf(AStringView url);

/// sites.json next to the executable.
APath sitesFile();

/// Lists from sites.json; a missing or empty zone falls back to the built-in list.
SiteLists loadSiteLists(const APath& file = sitesFile());

/// Writes `{zone: [[name, url], ...]}`. Returns false if the file could not be written.
bool saveSiteLists(const SiteLists& lists, const APath& file = sitesFile());

/// Parses sites.json text. Items are either [name, url] pairs or bare url strings.
SiteLists parseSiteLists(AStringView json);

}   // namespace net
