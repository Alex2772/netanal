#include "widgets/Flag.h"

#include <AUI/ASS/ASS.h>
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

// ---- flags -----------------------------------------------------------------------------------------------------

struct Stripes {
    AStringView code;
    AVector<uint32_t> colors;
};

const AVector<Stripes> H_FLAGS = {
    { "RU", { 0xffffff, 0x0039a6, 0xd52b1e } }, { "PL", { 0xffffff, 0xdc143c } },
    { "DE", { 0x000000, 0xdd0000, 0xffce00 } }, { "NL", { 0xae1c28, 0xffffff, 0x21468b } },
    { "AT", { 0xed2939, 0xffffff, 0xed2939 } }, { "HU", { 0xcd2a3e, 0xffffff, 0x436f4d } },
    { "BG", { 0xffffff, 0x00966e, 0xd62612 } }, { "LT", { 0xfdb913, 0x006a44, 0xc1272d } },
    { "EE", { 0x0072ce, 0x000000, 0xffffff } }, { "LU", { 0xed2939, 0xffffff, 0x00a1de } },
    { "CO", { 0xfcd116, 0x003893, 0xce1126 } }, { "AR", { 0x74acdf, 0xffffff, 0x74acdf } },
};

const AVector<Stripes> V_FLAGS = {
    { "FR", { 0x0055a4, 0xffffff, 0xef4135 } }, { "IT", { 0x009246, 0xffffff, 0xce2b37 } },
    { "IE", { 0x169b62, 0xffffff, 0xff883e } }, { "BE", { 0x000000, 0xfdda24, 0xef3340 } },
    { "RO", { 0x002b7f, 0xfcd116, 0xce1126 } },
};

/// Background and cross colours; GB is drawn the same way.
const AVector<Stripes> CROSS_FLAGS = {
    { "FI", { 0xffffff, 0x003580 } }, { "SE", { 0x006aa7, 0xfecc00 } }, { "NO", { 0xba0c2f, 0xffffff } },
    { "DK", { 0xc60c30, 0xffffff } }, { "IS", { 0x02529c, 0xffffff } }, { "GB", { 0x012169, 0xffffff } },
};

AOptional<Stripes> findFlag(const AVector<Stripes>& flags, AStringView code) {
    const auto it = std::find_if(flags.begin(), flags.end(), [&](const Stripes& s) { return s.code == code; });
    if (it == flags.end()) {
        return std::nullopt;
    }
    return *it;
}

struct CountryName {
    AStringView name;
    AStringView code;
};

constexpr auto COUNTRY_CODES = std::to_array<CountryName>({
    { "Russia", "RU" },        { "Russian Federation", "RU" }, { "Germany", "DE" },      { "Poland", "PL" },
    { "United States", "US" }, { "Netherlands", "NL" },        { "Luxembourg", "LU" },   { "Finland", "FI" },
    { "Sweden", "SE" },        { "France", "FR" },             { "United Kingdom", "GB" }, { "Australia", "AU" },
    { "Canada", "CA" },        { "Switzerland", "CH" },        { "Austria", "AT" },      { "Czechia", "CZ" },
    { "Estonia", "EE" },       { "Latvia", "LV" },             { "Lithuania", "LT" },    { "Turkey", "TR" },
    { "Kazakhstan", "KZ" },    { "Singapore", "SG" },          { "Japan", "JP" },        { "South Korea", "KR" },
    { "China", "CN" },         { "India", "IN" },              { "Brazil", "BR" },       { "Ukraine", "UA" },
    { "Belarus", "BY" },
});

class FlagView : public AViewContainer {
public:
    FlagView() {
        setLayout(std::make_unique<AStackedLayout>());
        mBadge = text("", { ".w700" }) AUI_OVERRIDE_STYLE { FontSize { 8_dp }, TextColor { rgb(0xe0e0e0) } };
        addView(mBadge);
        setCustomStyle({ FixedSize { 20_dp, 14_dp }, BackgroundSolid { rgb(0x37474f) }, AOverflow::HIDDEN });
        setVisibility(Visibility::GONE);
    }

    void setCountry(const AString& value) {
        mCode = countryCode(value);
        if (mCode.empty()) {
            setVisibility(Visibility::GONE);
            return;
        }
        const bool drawn = findFlag(H_FLAGS, mCode) || findFlag(V_FLAGS, mCode) || findFlag(CROSS_FLAGS, mCode) ||
                           mCode == "US";
        mBadge->setText(drawn ? AString() : AString(mCode.substr(0, 2)));
        setVisibility(Visibility::VISIBLE);
        redraw();
    }

    void render(ARenderContext ctx) override {
        AViewContainer::render(ctx);
        const auto w = float(getWidth());
        const auto h = float(getHeight());
        auto fill = [&](uint32_t color, glm::vec2 pos, glm::vec2 size) {
            ctx.render.rectangle(ASolidBrush { rgb(color) }, pos, size);
        };
        if (auto f = findFlag(H_FLAGS, mCode)) {
            const auto n = float(f->colors.size());
            for (size_t i = 0; i < f->colors.size(); ++i) {
                fill(f->colors[i], { 0, std::floor(i * h / n) }, { w, std::floor(h / n) + 1 });
            }
            return;
        }
        if (auto f = findFlag(V_FLAGS, mCode)) {
            const auto n = float(f->colors.size());
            for (size_t i = 0; i < f->colors.size(); ++i) {
                fill(f->colors[i], { std::floor(i * w / n), 0 }, { std::floor(w / n) + 1, h });
            }
            return;
        }
        if (auto f = findFlag(CROSS_FLAGS, mCode)) {
            fill(f->colors[0], { 0, 0 }, { w, h });
            fill(f->colors[1], { 0, std::floor(h * 2 / 5) }, { w, std::max(2.f, std::floor(h / 5)) });
            fill(f->colors[1], { std::floor(w * 2 / 5), 0 }, { std::max(2.f, std::floor(w / 5)), h });
            return;
        }
        if (mCode != "US") {
            return;
        }
        for (int i = 0; i < 7; ++i) {
            fill(i % 2 == 0 ? 0xb22234 : 0xffffff, { 0, std::floor(i * h / 7) }, { w, std::floor(h / 7) + 1 });
        }
        fill(0x3c3b6e, { 0, 0 }, { std::floor(w * 0.45f), std::floor(h * 0.55f) });
    }

private:
    AString mCode;
    _<ALabel> mBadge;
};

}   // namespace

AString countryCode(AStringView value) {
    const auto v = AString(value).trim();
    if (v.length() == 2 && std::all_of(v.begin(), v.end(), [](auto c) { return std::isalpha(int(c)); })) {
        return v.uppercase();
    }
    for (const auto& c : COUNTRY_CODES) {
        if (c.name == v) {
            return AString(c.code);
        }
    }
    return {};
}

_<AView> Flag::operator()() {
    return ui::view<FlagView> {} AUI_LET { bindSetter(country, it, &FlagView::setCountry); };
}
