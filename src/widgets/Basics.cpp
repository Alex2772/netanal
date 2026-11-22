#include "widgets/Basics.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/ADrawableView.h>
#include <AUI/View/AProgressBar.h>
#include <AUI/View/AText.h>

#include "Match.h"
#include "Theme.h"
#include "widgets/Palette.h"

using namespace ass;
using namespace declarative;
using namespace widgets;
using net::match;
using net::Severity;
using net::Verdict;

// ---- small building blocks -------------------------------------------------------------------------------------

_<ALabel> text(AString value, std::initializer_list<AString> classes, AOptional<AMetric> size) {
    return Label { std::move(value) }() AUI_LET {
        for (const auto& c : classes) {
            it->addAssName(c);
        }
        if (size) {
            it->setCustomStyle({ FontSize { *size } });
        }
    };
}

_<AView> wrapped(AString value, std::initializer_list<AString> classes, AOptional<AMetric> size) {
    auto t = AText::fromString(std::move(value));
    for (const auto& c : classes) {
        t->addAssName(c);
    }
    if (size) {
        t->setCustomStyle({ FontSize { *size }, Expanding { 1, 0 } });
    } else {
        t->setCustomStyle({ Expanding { 1, 0 } });
    }
    return t;
}

AUrl emojiUrl(AStringView name) { return AUrl(":emoji/{}.svg"_format(name)); }

_<AView> emoji(AStringView name, AMetric size) {
    return Icon { emojiUrl(name) } AUI_OVERRIDE_STYLE { FixedSize { size, size } };
}

_<AView> VerdictText::operator()() {
    return Label {}() AUI_LET {
        for (const auto& c : classes) {
            it->addAssName(c);
        }
        it->setCustomStyle({ ATextOverflow::ELLIPSIS });
        bindSetter(value, it, [](ALabel& label, const Verdict& verdict) {
            label.setText(verdict.value);
            for (auto s : { Severity::OK, Severity::WARN, Severity::BAD }) {
                label.setAssName(theme::severityClass(s), s == verdict.severity);
            }
        });
    };
}

_<ATabView> TabView::operator()() {
    return ui::view<ATabView> {} AUI_LET {
        for (auto& tab : tabs) {
            it->addTab(std::move(tab.content), tab.title);
        }
    };
}

_<AView> Caption::operator()() {
    return Label {}() AUI_LET {
        for (const auto& c : classes) {
            it->addAssName(c);
        }
        it->setCustomStyle({ FontSize { size } });
        bindSetter(text, it, [](ALabel& label, const AString& value) {
            label.setText(value);
            label.setVisibility(value.empty() ? Visibility::GONE : Visibility::VISIBLE);
        });
        if (color) {
            bindStyle(*color, it, [size = size](const AColor& c) -> ass::PropertyListRecursive {
                return { FontSize { size }, TextColor { c } };
            });
        }
    };
}

_<AView> Progress::operator()() {
    return _cast<AProgressBar>(ProgressBar { .progress = 0.f }()) AUI_LET {
        it->setCustomStyle({ FixedSize { {}, height }, Expanding { 1, 0 } });
        bindSetter(value, it, [](AProgressBar& bar, const AOptional<float>& fraction) {
            bar.setVisibility(fraction ? Visibility::VISIBLE : Visibility::GONE);
            bar.setValue(fraction.valueOr(0.f));
        });
    };
}
