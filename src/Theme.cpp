#include "Theme.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Platform/AWindow.h>
#include <AUI/View/AButton.h>
#include <AUI/View/ACheckBox.h>
#include <AUI/View/AProgressBar.h>
#include <AUI/View/AScrollbar.h>
#include <AUI/View/ATabView.h>
#include <AUI/View/ATextArea.h>

using namespace ass;
using net::Severity;

namespace theme {

namespace {

struct Palette {
    AColor bg, card, card2, border, text, muted;
    AColor btn, btnHover, btnPress, disabled, disabledBg;
    AColor listBg, itemHover, tableBg, tableAlt, header, headerText;
    AColor scroll, checkBorder, checkBg, inputBg, tabHover, onAccent;
};

AColor rgb(uint32_t v) { return AColor((v << 8) | 0xffu); }

Palette palette(bool dark) {
    if (dark) {
        return {
            .bg = rgb(0x121417), .card = rgb(0x1c1f24), .card2 = rgb(0x23282f), .border = rgb(0x2a2e35),
            .text = rgb(0xe0e0e0), .muted = rgb(0x8a9099), .btn = rgb(0x262a30), .btnHover = rgb(0x31363d),
            .btnPress = rgb(0x1f2328), .disabled = rgb(0x6a7078), .disabledBg = rgb(0x20242a),
            .listBg = rgb(0x171a1e), .itemHover = rgb(0x262a30), .tableBg = rgb(0x171a1e),
            .tableAlt = rgb(0x1b1e23), .header = rgb(0x20242a), .headerText = rgb(0x9e9e9e),
            .scroll = rgb(0x31363d), .checkBorder = rgb(0x3a3f46), .checkBg = rgb(0x171a1e),
            .inputBg = rgb(0x171a1e), .tabHover = rgb(0xd0d4d9), .onAccent = rgb(0x0b0c0e),
        };
    }
    return {
        .bg = rgb(0xf4f5f7), .card = rgb(0xffffff), .card2 = rgb(0xf8fafc), .border = rgb(0xe2e5ea),
        .text = rgb(0x1f2328), .muted = rgb(0x6b7280), .btn = rgb(0xeceef2), .btnHover = rgb(0xe0e3e8),
        .btnPress = rgb(0xd8dbe0), .disabled = rgb(0xa0a6ae), .disabledBg = rgb(0xeef0f3),
        .listBg = rgb(0xffffff), .itemHover = rgb(0xf0f2f5), .tableBg = rgb(0xffffff),
        .tableAlt = rgb(0xf7f8fa), .header = rgb(0xeceef2), .headerText = rgb(0x4b5563),
        .scroll = rgb(0xc8ccd2), .checkBorder = rgb(0xc8ccd2), .checkBg = rgb(0xffffff),
        .inputBg = rgb(0xffffff), .tabHover = rgb(0x3a4048), .onAccent = rgb(0xffffff),
    };
}

AColor lighten(AColor c, float f = 0.25f) {
    return { c.r + (1 - c.r) * f, c.g + (1 - c.g) * f, c.b + (1 - c.b) * f, c.a };
}

Palette gCurrent = palette(true);

}   // namespace

AColor chipColor(Severity severity) {
    switch (severity) {
        case Severity::OK:
            return rgb(0x1b5e20);
        case Severity::WARN:
            return rgb(0xe65100);
        case Severity::BAD:
            return rgb(0xb71c1c);
        case Severity::NEUTRAL:
            return rgb(0x455a64);
    }
    return {};
}

AColor textColor(Severity severity) {
    switch (severity) {
        case Severity::OK:
            return rgb(0x66bb6a);
        case Severity::WARN:
            return rgb(0xffa726);
        case Severity::BAD:
            return rgb(0xef5350);
        case Severity::NEUTRAL:
            return rgb(0x90a4ae);
    }
    return {};
}

AString severityClass(Severity severity) { return ".sev_" + AString(net::severityName(severity)); }

AColor cardColor() { return gCurrent.card; }
AColor trackColor() { return gCurrent.scroll; }

void apply(AColor accent, bool dark) {
    const auto p = gCurrent = palette(dark);
    const auto light = lighten(accent);
    const auto shadow = AColor(0, 0, 0, 90.f / 255.f);

    // AUI's defaults first: the views rely on them for layout
    static const auto DEFAULTS = AStylesheet().getRules();
    auto rules = DEFAULTS;
    rules << AVector<Rule> {
        { t<AView>(), TextColor { p.text }, Font { ":font/OpenSans-Regular.ttf" }, FontSize { 13_dp } },
        { t<AWindow>(), BackgroundSolid { p.bg }, Padding { 12_dp, 14_dp } },

        // font weights
        { c(".w600"), Font { ":font/OpenSans-Semibold.ttf" } },
        { c(".w700"), Font { ":font/OpenSans-Bold.ttf" } },
        { c(".w800"), Font { ":font/OpenSans-ExtraBold.ttf" } },
        { c(".muted"), TextColor { p.muted } },

        // severity colours
        { c(".sev_ok"), TextColor { textColor(Severity::OK) } },
        { c(".sev_warn"), TextColor { textColor(Severity::WARN) } },
        { c(".sev_bad"), TextColor { textColor(Severity::BAD) } },

        // cards
        {
            c(".card"),
            BackgroundSolid { p.card },
            BorderRadius { 14_dp },
            Border { 1_dp, p.border },
            BoxShadow { 0, 4_dp, 24_dp, 0, shadow },
        },
        { c(".summary"), BackgroundGradient { p.card, p.card2, 90_deg }, BoxShadow { 0, 6_dp, 32_dp, 0, shadow } },
        { c::hover(".card"), Border { 1_dp, accent } },
        { c(".section_header"), BorderBottom { 1_dp, rgb(0x37474f) }, Padding { 0, 0, 4_dp }, Margin { 10_dp, 0, 0 } },

        // buttons
        {
            t<AButton>(),
            BackgroundSolid { p.btn },
            BackgroundGradient { nullptr },
            TextColor { p.text },
            Border { nullptr },
            BorderRadius { 8_dp },
            Padding { 8_dp, 16_dp },
            BoxShadow { nullptr },
            MinSize { 0, 0 },
            Font { ":font/OpenSans-Semibold.ttf" },
        },
        { t<AButton>::hover(), BackgroundSolid { p.btnHover }, Border { nullptr }, BoxShadow { nullptr } },
        { t<AButton>::active(), BackgroundSolid { p.btnPress } },
        { t<AButton>::disabled(), TextColor { p.disabled }, BackgroundSolid { p.disabledBg }, Border { nullptr } },
        { c(".primary"), BackgroundSolid { accent }, TextColor { p.onAccent }, Font { ":font/OpenSans-Bold.ttf" } },
        { c::hover(".primary"), BackgroundSolid { light } },
        { c::disabled(".primary"), TextColor { p.disabled }, BackgroundSolid { p.disabledBg } },

        // tabs
        {
            t<ATabButtonView>(),
            BackgroundSolid { nullptr },
            Padding { 9_dp, 20_dp },
            TextColor { p.muted },
            BorderBottom { 2_dp, AColor::TRANSPARENT_BLACK },
            FontSize { 13_dp },
            Font { ":font/OpenSans-Semibold.ttf" },
        },
        { Selected(t<ATabButtonView>()), TextColor { p.text }, BorderBottom { 2_dp, accent } },
        { t<ATabButtonView>::hover(), TextColor { p.tabHover }, BackgroundSolid { nullptr } },
        { t<ATabView>() > t<APageView>(), Border { 1_dp, p.border }, BorderRadius { 10_dp }, Padding { 9_dp } },

        // progress bars
        { t<AProgressBar>(), BackgroundSolid { p.btn }, BorderRadius { 4_dp }, MinSize { 0, 0 } },
        { t<AProgressBar::Inner>(), BackgroundSolid { accent }, BorderRadius { 4_dp } },

        // check box
        { t<ACheckBox>(), TextColor { p.muted }, LayoutSpacing { 8_dp } },
        {
            t<ACheckBox::Box>(),
            FixedSize { 16_dp, 16_dp },
            BorderRadius { 4_dp },
            Border { 2_dp, p.checkBorder },
            BackgroundSolid { p.checkBg },
            BackgroundGradient { nullptr },
        },
        {
            Selected(t<ACheckBox::Box>()),
            BackgroundSolid { accent },
            BackgroundGradient { accent, accent, 0_deg },
            Border { 2_dp, accent },
            BackgroundImage { ":uni/svg/checkbox.svg", p.onAccent },
        },

        // text areas
        {
            t<ATextArea>(),
            BackgroundSolid { p.inputBg },
            TextColor { p.text },
            Border { 1_dp, p.border },
            BorderRadius { 10_dp },
            Padding { 8_dp },
        },

        { c(".textbox"), BackgroundSolid { p.inputBg }, Border { 1_dp, p.border }, BorderRadius { 10_dp },
          Padding { 8_dp } },

        // scroll bars
        { t<AScrollbarHandle>(), BackgroundSolid { p.scroll }, BorderRadius { 5_dp } },
        { t<AScrollbarHandle>::hover(), BackgroundSolid { p.scroll } },
        { t<AScrollbarButton>(), Visibility::GONE },

        // left navigation list on "Система"
        { c(".navlist"), BackgroundSolid { p.listBg }, BorderRadius { 10_dp }, Padding { 4_dp } },
        { c(".navitem"), Padding { 8_dp, 12_dp }, BorderRadius { 7_dp }, TextColor { p.muted } },
        { c::hover(".navitem"), BackgroundSolid { p.itemHover } },
        {
            c(".navitem_selected"),
            BackgroundSolid { accent },
            TextColor { p.onAccent },
            Font { ":font/OpenSans-Semibold.ttf" },
        },

        // tables
        { c(".table"), BackgroundSolid { p.tableBg } },
        {
            c(".th"),
            BackgroundSolid { p.header },
            TextColor { p.headerText },
            Padding { 7_dp },
            Font { ":font/OpenSans-Semibold.ttf" },
        },
        { c(".td"), Padding { 4_dp, 7_dp }, BorderBottom { 1_dp, p.border } },
        // cells of a table whose columns share the width
        { c(".elide"), ATextOverflow::ELLIPSIS },
        { c(".td_alt"), BackgroundSolid { p.tableAlt } },

        // rows on "Сводка"
        { c(".finding"), BackgroundSolid { p.card }, BorderRadius { 8_dp }, Padding { 8_dp, 12_dp, 8_dp, 10_dp } },
    };
    AStylesheet::global().setRules(std::move(rules));
}

}   // namespace theme
