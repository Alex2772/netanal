#pragma once

#include "widgets/Dynamic.h"

/// "●" of a colour that may be reactive.
struct Dot {
    In<AColor> color;
    AMetric size;
    _<AView> operator()();
};

/// History of ping / speed values.
struct Sparkline {
    In<AVector<double>> values;
    In<AColor> color;
    AMetric height;
    _<AView> operator()();
};

/// Thin bar that runs while `active`.
struct ActivityBar {
    In<bool> active;
    _<AView> operator()();
};
