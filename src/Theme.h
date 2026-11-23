#pragma once

#include <array>

#include <AUI/Common/AColor.h>
#include <AUI/Common/AString.h>

#include "Severity.h"

namespace theme {

struct Accent {
    AStringView name;
    AColor color;
};

inline const auto ACCENTS = std::to_array<Accent>({
  { .name = "Бирюзовый", .color = AColor(0x00bcd4ffu) },
  { .name = "Синий", .color = AColor(0x42a5f5ffu) },
  { .name = "Фиолетовый", .color = AColor(0xab47bcffu) },
  { .name = "Зелёный", .color = AColor(0x66bb6affu) },
  { .name = "Янтарный", .color = AColor(0xffb300ffu) },
  { .name = "Розовый", .color = AColor(0xec407affu) },
});

/// Chip background (zone status, finding stripe).
AColor chipColor(net::Severity severity);

/// Coloured value text.
AColor textColor(net::Severity severity);

/// ".sev_ok" etc.: the ASS class that colours a value by severity.
AString severityClass(net::Severity severity);

inline const AColor MONITOR_OFF = AColor(0x757575ffu);
inline const AColor MUTED_GREY = AColor(0x8a9099ffu);
inline const AColor INFO_BLUE = AColor(0x4fc3f7ffu);

/// Material theme (dark or light) with an accent colour. Replaces the global stylesheet.
void apply(AColor accent, bool dark);

/// Card background of the current theme, for custom-drawn views.
AColor cardColor();
AColor trackColor();

}   // namespace theme
