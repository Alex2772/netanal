#pragma once

#include <AUI/Common/AColor.h>
#include <AUI/Util/UIBuildingHelpers.h>

/// Colours shared by the widgets, not part of the theme.
namespace widgets {

inline AColor rgb(uint32_t v) { return AColor((v << 8) | 0xffu); }

inline const AColor OK_GREEN = rgb(0x66bb6a);
inline const AColor WARN_ORANGE = rgb(0xffa726);
inline const AColor BAD_RED = rgb(0xef5350);
inline const AColor NEUTRAL_GREY = rgb(0x90a4ae);
inline const AColor PING_CYAN = rgb(0x00bcd4);
inline const AColor IP_TEAL = rgb(0x26a69a);

namespace ui = aui::ui_building;

}   // namespace widgets
