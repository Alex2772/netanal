#pragma once

#include <variant>

#include "Online.h"
#include "Severity.h"
#include "widgets/Dynamic.h"

struct DetailRow {
    AString label;
    In<net::Verdict> value;
    /// Empty: no flag.
    In<AString> country = AString();
};

/// Card with an emoji title and "parameter ... value" rows.
struct DetailCard {
    AStringView icon;
    AString title;
    AVector<DetailRow> rows;
    _<AView> operator()();
};

struct SummaryItem {
    AString label;
    AString value;
    net::Severity severity;
};

enum class SummaryState { OK, WARN, BAD, PENDING };

namespace check {
struct Idle {};
struct Running {
    size_t done;
    size_t total;
    AString counts;
};
struct Finished {
    AString text;
};
}   // namespace check

/// Progress line of the summary card.
using CheckProgress = std::variant<check::Idle, check::Running, check::Finished>;

/// The verdict "ВСЁ ОК / НЕ ОК" with the list of findings.
struct SummaryCard {
    In<SummaryState> state;
    In<AVector<SummaryItem>> items;
    In<CheckProgress> progress;
    _<AView> operator()();
};

/// Background tunnel monitor: what is checked and the result.
struct MonitorCard {
    /// Empty while monitoring is off.
    In<AOptional<net::MonitorResult>> result;
    In<AString> lastCheck;
    /// Empty while monitoring is off.
    In<AOptional<int>> secondsLeft;
    In<bool> enabled;
    declarative::contract::Slot<> onToggle;
    _<AView> operator()();
};

/// What the zone card shows, filled by the online check.
struct ZoneModel {
    AProperty<net::ZoneStats> stats;
    /// Empty while the IP is being detected.
    AProperty<AOptional<net::ZoneIp>> ip;
    AProperty<AVector<double>> pingHistory;
    AProperty<AVector<double>> speedHistory;
};

/// Zone card: status chip, external IP with a flag, ping / DNS / speed / sites, sparklines.
struct ZoneCard {
    net::Zone zone;
    _<ZoneModel> model;
    In<AColor> accent;
    _<AView> operator()();
};
