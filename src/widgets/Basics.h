#pragma once

#include <AUI/Url/AUrl.h>
#include <AUI/View/AButton.h>
#include <AUI/View/ALabel.h>
#include <AUI/View/ATabView.h>
#include <AUI/View/ATextArea.h>

#include "Severity.h"
#include "widgets/Dynamic.h"

/// Label with ASS classes and an optional font size.
_<ALabel> text(AString value, std::initializer_list<AString> classes = {}, AOptional<AMetric> size = {});

/// Word-wrapping text.
_<AView> wrapped(AString value, std::initializer_list<AString> classes = {}, AOptional<AMetric> size = {});

/// Noto emoji from assets/emoji: the font renderer has no colour glyphs. For a reactive one use
/// `Icon { AUI_REACT(emojiUrl(...)) }`.
AUrl emojiUrl(AStringView name);
_<AView> emoji(AStringView name, AMetric size);

/// Value of a card row, coloured by its severity.
struct VerdictText {
    In<net::Verdict> value;
    AVector<AString> classes = { ".w600" };
    _<AView> operator()();
};

/// Single-line label that follows `text` (and `color`); hidden while the text is empty.
struct Caption {
    In<AString> text;
    AMetric size = 12_dp;
    AOptional<In<AColor>> color;
    AVector<AString> classes;
    _<AView> operator()();
};

/// Progress bar; hidden while `value` is empty.
struct Progress {
    In<AOptional<float>> value;
    AMetric height;
    _<AView> operator()();
};

/// Multi-line text editor.
struct TextArea : aui::ui_building::view<ATextArea> {
    using view::view;
};

struct Tab {
    AString title;
    _<AView> content;
};

struct TabView {
    AVector<Tab> tabs;
    _<ATabView> operator()();
};
