#pragma once

#include <algorithm>
#include <cmath>

#include <AUI/Common/AColor.h>

/// The tray icon: a filled circle of the monitor colour, as the original's _make_icon draws it.
namespace tray_icon {

inline constexpr int SIZE = 32;

/// How much of pixel (x, y) the circle covers: ellipse (3, 3, 26, 26) with a 1 px soft edge.
inline float coverage(int x, int y) {
    const float d = std::hypot(float(x) + 0.5f - 16.f, float(y) + 0.5f - 16.f);
    return std::clamp(13.5f - d, 0.f, 1.f);
}

}   // namespace tray_icon
