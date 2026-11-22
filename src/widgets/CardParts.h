#pragma once

#include <AUI/ASS/ASS.h>
#include <AUI/View/AViewContainer.h>

#include "Severity.h"

/// Pieces of the cards in Cards.h.
namespace widgets {

/// "●  label ............ value" row of SummaryCard / MonitorCard.
_<AView> dotItem(const AString& label, const AString& value, net::Severity severity, AMetric dotSize);

_<AView> cardTitle(AStringView icon, const AString& title);

_<AViewContainer> card(AVector<_<AView>> views, ass::PropertyListRecursive style);

}   // namespace widgets
