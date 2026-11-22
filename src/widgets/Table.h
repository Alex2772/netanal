#pragma once

#include <AUI/Common/AColor.h>

#include "widgets/Dynamic.h"

struct Cell {
    AString value;
    AOptional<AColor> color;

    bool operator==(const Cell&) const = default;
};

/// Table whose columns share the width equally. New rows are appended, the old ones are kept.
struct StretchTable {
    AVector<AString> columns;
    In<AVector<AVector<Cell>>> rows;
    _<AView> operator()();
};

/// Table whose columns fit their contents (a section of "Система").
_<AView> fitTable(const AVector<AString>& columns, const AVector<AVector<AString>>& rows);
