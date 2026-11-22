#include "widgets/Table.h"

#include <AUI/ASS/ASS.h>
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

/// Columns as vertical stacks: every column is as wide as its widest cell, rows line up because cells are single-line
/// labels of equal height.
/// Cell of a table whose columns share the width: may get narrower than its text, the rest is elided.
class ElidedLabel : public ALabel {
public:
    using ALabel::ALabel;

protected:
    AMinMaxAxis onComputeIntrinsicMinMaxAxis(int height) override {
        auto axis = ALabel::onComputeIntrinsicMinMaxAxis(height);
        axis.min = 0;
        return axis;
    }
};

class ColumnTable : public AViewContainer {
public:
    ColumnTable(const AVector<AString>& columns, bool stretch) : mStretch(stretch) {
        setLayout(std::make_unique<AHorizontalLayout>());
        addAssName(".table");
        for (const auto& name : columns) {
            auto col = Vertical { cellLabel(name, ".th") } AUI_OVERRIDE_STYLE { LayoutSpacing { 0 } };
            if (stretch) {
                col->setCustomStyle({ Expanding { 1, 0 } });
            }
            addView(col);
            mColumns << col;
        }
        if (stretch) {
            setCustomStyle({ Expanding { 1, 0 } });
        }
    }

    void addRow(const AVector<Cell>& cells) {
        for (size_t i = 0; i < mColumns.size(); ++i) {
            const auto cell = i < cells.size() ? cells[i] : Cell {};
            auto label = cellLabel(cell.value.empty() ? AString(" ") : cell.value, ".td");
            if (mRows % 2 == 1) {
                label->addAssName(".td_alt");
            }
            if (cell.color) {
                label->setCustomStyle({ TextColor { *cell.color } });
            }
            mColumns[i]->addView(label);
        }
        ++mRows;
    }

    /// Appends the rows it has not shown yet; starts over when the list got shorter.
    void setRows(const AVector<AVector<Cell>>& rows) {
        if (rows.size() < mRows) {
            clear();
        }
        for (size_t i = mRows; i < rows.size(); ++i) {
            addRow(rows[i]);
        }
    }

private:
    AVector<_<AViewContainer>> mColumns;
    size_t mRows = 0;
    bool mStretch;

    /// In a stretched table long values are elided instead of widening it.
    _<ALabel> cellLabel(AString value, const AString& klass) const {
        _<ALabel> label =
            mStretch ? _<ALabel>(ui::view<ElidedLabel> { std::move(value) }()) : Label { std::move(value) }();
        label->addAssName(klass);
        label->setAssName(".elide", mStretch);
        return label;
    }

    void clear() {
        for (const auto& col : mColumns) {
            while (col->getViews().size() > 1) {
                col->removeView(col->getViews().size() - 1);
            }
        }
        mRows = 0;
    }
};

}   // namespace

_<AView> StretchTable::operator()() {
    return ui::view<ColumnTable> { columns, true } AUI_LET { bindSetter(rows, it, &ColumnTable::setRows); };
}

_<AView> fitTable(const AVector<AString>& columns, const AVector<AVector<AString>>& rows) {
    return ui::view<ColumnTable> { columns, false } AUI_LET {
        for (const auto& r : rows) {
            AVector<Cell> cells;
            for (const auto& v : r) {
                cells << Cell { .value = v };
            }
            it->addRow(cells);
        }
    };
}
