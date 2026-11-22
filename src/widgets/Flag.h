#pragma once

#include "widgets/Dynamic.h"

/// Two-letter country code from a code or an English name; empty if unknown.
AString countryCode(AStringView value);

/// Flag drawn from stripes, or a badge with the code; hidden for an unknown country.
struct Flag {
    In<AString> country;
    _<AView> operator()();
};
