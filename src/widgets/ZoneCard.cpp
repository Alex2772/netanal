#include "widgets/Cards.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>

#include "Match.h"
#include "Report.h"
#include "Theme.h"
#include "widgets/Basics.h"
#include "widgets/CardParts.h"
#include "widgets/Flag.h"
#include "widgets/Graphics.h"
#include "widgets/Palette.h"

using namespace ass;
using namespace declarative;
using namespace widgets;
using net::match;
using net::Severity;
using net::Verdict;

namespace {

// ---- zone card values ------------------------------------------------------------------------------------------

Verdict pingVerdict(const net::ZoneStats& z) {
    if (auto avg = net::filteredAvg(z.lats)) {
        return { "{} мс"_format(std::lround(*avg)), net::pingSeverity(*avg) };
    }
    return { "—" };
}

Verdict dnsVerdict(const net::ZoneStats& z) {
    if (auto avg = net::filteredAvg(z.dnsMs)) {
        return { "{} мс"_format(std::lround(*avg)), net::dnsSeverity(*avg) };
    }
    return { "—" };
}

Verdict speedVerdict(const net::ZoneStats& z) {
    return match(
        z.speed,
        [](const net::Speed& s) -> Verdict {
            return { "{:.0f} Мбит/с"_format(s.mbps), net::speedSeverity(s.mbps) };
        },
        [](const net::Failure&) -> Verdict { return { "нет", Severity::BAD }; },
        [](net::SpeedPending) -> Verdict { return { "…" }; });
}

Verdict sitesVerdict(const net::ZoneStats& z) {
    if (z.total == 0) {
        return { "—" };
    }
    return { "{}/{}"_format(z.ok, z.total), net::zoneStatus(z.ok, z.total).severity };
}

/// "пинг, мс · 10–102": the caption with the range of `values`.
AString rangeCaption(AStringView caption, const AVector<double>& values) {
    if (values.empty()) {
        return AString(caption);
    }
    const auto [mn, mx] = std::minmax_element(values.begin(), values.end());
    return "{} · {:.0f}–{:.0f}"_format(caption, *mn, *mx);
}

AString ipText(const AOptional<net::ZoneIp>& ip) {
    if (!ip) {
        return "IP: …";
    }
    if (!ip->ip) {
        return "не определён";
    }
    if (ip->geo && !ip->geo->country.empty()) {
        return "{} · {}"_format(*ip->ip, ip->geo->country);
    }
    return *ip->ip;
}

AString ipCountry(const AOptional<net::ZoneIp>& ip) {
    if (!ip || !ip->ip || !ip->geo) {
        return {};
    }
    return ip->geo->countryCode.empty() ? ip->geo->country : ip->geo->countryCode;
}

}   // namespace

_<AView> ZoneCard::operator()() {
    auto c = card({}, { Padding { 14_dp, 16_dp }, LayoutSpacing { 6_dp }, Expanding { 1, 0 } });
    // AUI_REACT copies by [=], which would capture `this` of the builder; use a local copy
    const auto m = model;
    const auto stats = [m]() -> const net::ZoneStats& { return *m->stats; };
    In<Severity> severity = AUI_REACT(Severity(net::zoneStatus(stats().ok, stats().total).severity));
    // zone status: the coloured box spans the card
    auto chip = Centered {
        Caption {
            .text = AUI_REACT(AString(net::zoneStatus(stats().ok, stats().total).value)),
            .size = 15_dp,
            .color = AColor::WHITE,
            .classes = { ".w800" },
        },
    } AUI_LET {
        bindStyle(severity, it, [](Severity s) -> ass::PropertyListRecursive {
            return {
                Expanding { 1, 0 },
                BackgroundSolid { theme::chipColor(s) },
                BorderRadius { 8_dp },
                Padding { 8_dp },
            };
        });
    };
    const auto param = [&](AString label, In<Verdict> value) {
        return Horizontal {
            text(std::move(label), { ".muted" }),
            SpacerExpanding {},
            VerdictText { std::move(value), { ".w700" } },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } };
    };
    c->addViews({
        text(AString(net::zoneName(zone)), { ".w700" }, 15_dp),
        Horizontal {
            Flag { AUI_REACT(ipCountry(*m->ip)) },
            Caption { .text = AUI_REACT(ipText(*m->ip)), .color = IP_TEAL },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } },
        chip,
        param("Пинг", AUI_REACT(pingVerdict(stats()))),
        param("DNS", AUI_REACT(dnsVerdict(stats()))),
        param("Скорость", AUI_REACT(speedVerdict(stats()))),
        param("Сайтов", AUI_REACT(sitesVerdict(stats()))),
        Progress {
            AUI_REACT(AOptional<float>(stats().total ? float(stats().ok) / float(stats().total) : 0.f)),
            6_dp,
        },
        Sparkline { .values = AUI_REACT(*m->pingHistory), .color = std::move(accent), .height = 42_dp },
        Horizontal {
            emoji("chart", 12_dp),
            Caption {
                .text = AUI_REACT(rangeCaption("пинг, мс", stats().lats)),
                .size = 11_dp,
                .classes = { ".muted" },
            },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 4_dp } },
        Sparkline { .values = AUI_REACT(*m->speedHistory), .color = OK_GREEN, .height = 32_dp },
        Horizontal {
            emoji("signal", 12_dp),
            Caption {
                .text = AUI_REACT(rangeCaption("скорость, Мбит/с", *m->speedHistory)),
                .size = 11_dp,
                .classes = { ".muted" },
            },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 4_dp } },
    });
    return c;
}
