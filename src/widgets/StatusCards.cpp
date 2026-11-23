#include "widgets/Cards.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/ADrawableView.h>

#include "Match.h"
#include "Report.h"
#include "Theme.h"
#include "widgets/Basics.h"
#include "widgets/CardParts.h"
#include "widgets/Graphics.h"
#include "widgets/Palette.h"

using namespace ass;
using namespace declarative;
using namespace widgets;
using net::match;
using net::Severity;
using net::Verdict;

namespace {

struct SummaryHead {
    AString icon;
    AString title;
    AColor color;
};

SummaryHead summaryHead(SummaryState state) {
    switch (state) {
        case SummaryState::OK:
            return { .icon = "check", .title = "ВСЁ ОК", .color = OK_GREEN };
        case SummaryState::BAD:
            return { .icon = "cross", .title = "НЕ ОК", .color = BAD_RED };
        case SummaryState::PENDING:
            return { .icon = "hourglass", .title = "ИДЁТ ПРОВЕРКА", .color = NEUTRAL_GREY };
        case SummaryState::WARN:
            break;
    }
    return { .icon = "warning", .title = "ЕСТЬ ЗАМЕЧАНИЯ", .color = WARN_ORANGE };
}

struct Look {
    AString text;
    AColor color;
};

Look checkLine(const CheckProgress& progress) {
    return match(
        progress, [](check::Idle) { return Look { .text = "", .color = theme::MUTED_GREY }; },
        [](const check::Running& r) {
            return Look { .text = "Сайты: {} / {}"_format(r.done, r.total), .color = WARN_ORANGE };
        },
        [](const check::Finished& f) { return Look { .text = f.text, .color = OK_GREEN }; });
}

AOptional<float> checkFraction(const CheckProgress& progress) {
    if (auto r = std::get_if<check::Running>(&progress)) {
        return r->total ? float(r->done) / float(r->total) : 0.f;
    }
    return std::nullopt;
}

AString checkCounts(const CheckProgress& progress) {
    if (auto r = std::get_if<check::Running>(&progress)) {
        return r->counts;
    }
    return {};
}

_<AView> dotList(const AVector<SummaryItem>& items, AMetric dotSize) {
    return Vertical {} AUI_LET {
        for (const auto& item : items) {
            it->addView(dotItem(item.label, item.value, item.severity, dotSize));
        }
        it->setCustomStyle({ LayoutSpacing { 3_dp } });
    };
}

}   // namespace

_<AView> SummaryCard::operator()() {
    auto c = card({}, { Padding { 14_dp, 20_dp, 16_dp, 18_dp }, LayoutSpacing { 8_dp }, Expanding { 3, 0 } });
    c->addAssName(".summary");
    auto head = share(std::move(state), c);
    auto check = share(std::move(progress), c);
    In<AColor> stripeColor = AUI_REACT(AColor(summaryHead(*head).color));
    c->addViews({
        Horizontal {
            Stacked {} AUI_LET {
                bindStyle(stripeColor, it, [](const AColor& color) -> ass::PropertyListRecursive {
                    return { FixedSize { 4_dp, {} }, BackgroundSolid { color }, BorderRadius { 2_dp } };
                });
            },
            Icon { AUI_REACT(emojiUrl(summaryHead(*head).icon)) } AUI_OVERRIDE_STYLE { FixedSize { 30_dp, 30_dp } },
            Caption {
                .text = AUI_REACT(AString(summaryHead(*head).title)),
                .size = 18_dp,
                .color = AUI_REACT(AColor(summaryHead(*head).color)),
                .classes = { ".w800" },
            },
            SpacerExpanding {},
        }
        AUI_OVERRIDE_STYLE { LayoutSpacing { 12_dp } },
            Caption {
                .text = AUI_REACT(AString(checkLine(*check).text)),
                .size = 11_dp,
                .color = AUI_REACT(AColor(checkLine(*check).color)),
            },
            Progress { .value = AUI_REACT(checkFraction(*check)), .height = 4_dp },
            Caption { .text = AUI_REACT(checkCounts(*check)), .size = 11_dp, .classes = { ".muted" } },
            Dynamic<AVector<SummaryItem>> {
                .value = std::move(items),
                .view = [](const AVector<SummaryItem>& list) { return dotList(list, 8_dp); },
            },
        });
    return c;
}

namespace {

Look monitorLook(const AOptional<net::MonitorResult>& result) {
    if (!result) {
        return { .text = "выключен", .color = theme::MUTED_GREY };
    }
    switch (result->state) {
        case net::MonitorState::OK:
            return { .text = "туннель в норме", .color = OK_GREEN };
        case net::MonitorState::SUSPECT:
            return { .text = "есть сомнения", .color = WARN_ORANGE };
        case net::MonitorState::BAD:
            return { .text = "туннель нестабилен", .color = BAD_RED };
        case net::MonitorState::OFF:
            break;
    }
    return { .text = "VPN выключен", .color = theme::MONITOR_OFF };
}

AVector<SummaryItem> monitorItems(const AOptional<net::MonitorResult>& result) {
    AVector<SummaryItem> items;
    if (!result) {
        return items;
    }
    for (const auto& c : result->checks) {
        items << SummaryItem { .label = c.label, .value = c.value, .severity = c.severity };
    }
    return items;
}

}   // namespace

_<AView> MonitorCard::operator()() {
    auto c = card({}, { Padding { 12_dp, 16_dp, 14_dp }, LayoutSpacing { 6_dp }, Expanding { 2, 0 } });
    auto monitor = share(std::move(result), c);
    const auto left = [left = share(std::move(secondsLeft), c)] { return **left; };
    auto last = share(std::move(lastCheck), c);
    auto on = share(std::move(enabled), c);
    c->addViews({
      cardTitle("antenna", "Мониторинг туннеля"),
      Horizontal {
        Dot { .color = AUI_REACT(AColor(monitorLook(*monitor).color)), .size = 9_dp },
        Caption {
          .text = AUI_REACT(AString(monitorLook(*monitor).text)),
          .color = AUI_REACT(AColor(monitorLook(*monitor).color)),
        },
        SpacerExpanding {},
      } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } },
      Dynamic<AVector<SummaryItem>> {
        .value = AUI_REACT(monitorItems(*monitor)),
        .view = [](const AVector<SummaryItem>& list) { return dotList(list, 7_dp); },
      },
      Caption { .text = AUI_REACT("последняя: " + **last), .size = 11_dp, .classes = { ".muted" } },
      Progress { .value = AUI_REACT(AOptional<float>(float(60 - left().valueOr(60)) / 60.f)), .height = 4_dp },
      Caption {
        .text = AUI_REACT(left() ? "следующая через {} с"_format(*left()) : AString("следующая: —")),
        .size = 11_dp,
        .classes = { ".muted" },
      },
      Button { .content = Label { AUI_REACT(AString(**on ? "Пауза" : "Включить")) }, .onClick = std::move(onToggle) },
    });
    return c;
}
