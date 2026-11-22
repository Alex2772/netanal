#include "widgets/Graphics.h"

#include <chrono>

#include <AUI/ASS/ASS.h>
#include <AUI/Platform/AWindow.h>
#include <AUI/Render/IRenderer.h>
#include <AUI/Util/UIBuildingHelpers.h>

#include "Match.h"
#include "Theme.h"
#include "widgets/Basics.h"
#include "widgets/Palette.h"

using namespace ass;
using namespace declarative;
using namespace widgets;
using net::match;
using net::Severity;
using net::Verdict;

namespace {

// ---- custom-drawn views ----------------------------------------------------------------------------------------

class SparklineView : public AView {
public:
    explicit SparklineView(AMetric height) {
        setCustomStyle({ FixedSize { {}, height }, MinSize { 120_dp, {} }, Expanding { 1, 0 } });
    }

    void setValues(const AVector<double>& values) {
        mValues = values;
        redraw();
    }

    void setColor(const AColor& color) {
        mColor = color;
        redraw();
    }

    void render(ARenderContext ctx) override {
        AView::render(ctx);
        const auto w = float(getWidth());
        const auto h = float(getHeight());
        if (mValues.size() < 2) {
            ctx.render.line(ASolidBrush { theme::trackColor() }, { 0, h / 2 }, { w, h / 2 });
            return;
        }
        const auto [mnIt, mxIt] = std::minmax_element(mValues.begin(), mValues.end());
        const auto mn = *mnIt;
        const auto mx = *mxIt == mn ? mn + 1.0 : *mxIt;
        const auto n = mValues.size();
        const auto pad = 2_dp;
        AVector<glm::vec2> points;
        for (size_t i = 0; i < n; ++i) {
            const auto x = float(i) * (w - 2 * pad.getValuePx()) / float(n - 1) + pad.getValuePx();
            const auto y =
                h - 2 * pad.getValuePx() - float((mValues[i] - mn) * (h - 4 * pad.getValuePx()) / (mx - mn));
            points << glm::vec2 { x, y };
        }
        ctx.render.lines(ASolidBrush { mColor }, points, ABorderStyle::Solid {}, AMetric(1.6f, AMetric::T_DP));
    }

private:
    AVector<double> mValues;
    AColor mColor;
};

class ActivityView : public AView {
public:
    ActivityView() { setCustomStyle({ FixedSize { {}, 3_dp }, Expanding { 1, 0 }, BorderRadius { 1_dp } }); }

    void render(ARenderContext ctx) override {
        AView::render(ctx);
        using namespace std::chrono;
        const auto w = float(getWidth());
        const auto t =
            float(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count() % 1600) / 1600.f;
        const auto chunk = w * 0.3f;
        const auto x = -chunk + t * (w + chunk);
        ctx.render.rectangle(ASolidBrush { theme::trackColor() }, { 0, 0 }, { w, float(getHeight()) });
        ctx.render.rectangle(ASolidBrush { AStylesheet::getOsThemeColor() }, { std::max(0.f, x), 0 },
                             { std::min(w, x + chunk) - std::max(0.f, x), float(getHeight()) });
        redraw();
    }
};

}   // namespace

_<AView> Dot::operator()() {
    return Stacked {} AUI_LET {
        bindStyle(color, it, [size = size](const AColor& c) -> ass::PropertyListRecursive {
            return {
                FixedSize { size, size },
                BorderRadius { AMetric(size.getValueDp() / 2, AMetric::T_DP) },
                BackgroundSolid { c },
            };
        });
    };
}

_<AView> Sparkline::operator()() {
    return ui::view<SparklineView> { height } AUI_LET {
        bindSetter(values, it, &SparklineView::setValues);
        bindSetter(color, it, &SparklineView::setColor);
    };
}

_<AView> ActivityBar::operator()() {
    return ui::view<ActivityView> {} AUI_LET {
        bindSetter(active, it, [](AView& bar, bool on) {
            bar.setVisibility(on ? Visibility::VISIBLE : Visibility::GONE);
        });
    };
}
