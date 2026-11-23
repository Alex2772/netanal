#include "widgets/CardParts.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>

#include "Match.h"
#include "Theme.h"
#include "widgets/Basics.h"
#include "widgets/Cards.h"
#include "widgets/Flag.h"
#include "widgets/Graphics.h"
#include "widgets/Palette.h"

using namespace ass;
using namespace declarative;
using namespace widgets;
using net::match;
using net::Severity;
using net::Verdict;

namespace widgets {

_<AView> dotItem(const AString& label, const AString& value, Severity severity, AMetric dotSize) {
    const auto color = severity == Severity::NEUTRAL ? NEUTRAL_GREY : theme::textColor(severity);
    return Horizontal {
        Centered { Dot { .color = color, .size = dotSize } } AUI_OVERRIDE_STYLE { Padding { 0, 2_dp } },
        text(label, { ".muted" }, 12_dp),
        SpacerExpanding {},
        text(value, { ".w600" }) AUI_OVERRIDE_STYLE { FontSize { 12_dp }, TextColor { color } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
}

_<AView> cardTitle(AStringView icon, const AString& title) {
    return Horizontal {
        emoji(icon, 16_dp),
        text(title, { ".w700" }, 14_dp),
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
}

_<AViewContainer> card(AVector<_<AView>> views, ass::PropertyListRecursive style) {
    return Vertical {} AUI_LET {
        it->addViews(std::move(views));
        it->addAssName(".card");
        it->setCustomStyle(std::move(style));
    };
}

}   // namespace widgets

_<AView> DetailCard::operator()() {
    auto lines = Vertical {} AUI_OVERRIDE_STYLE { LayoutSpacing { 4_dp } };
    for (auto& r : rows) {
        lines->addView(Horizontal {
          text(r.label, { ".muted" }),
          SpacerExpanding {},
          Flag { std::move(r.country) },
          VerdictText { .value = std::move(r.value) },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } });
    }
    return card(
        {
            cardTitle(icon, title),
            lines,
        },
        { Padding { 12_dp, 16_dp, 14_dp }, LayoutSpacing { 6_dp }, Expanding { 1, 0 } });
}
