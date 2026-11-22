#pragma once

#include <AUI/IO/APath.h>

#include "System.h"

namespace net {

/// Plain-text report, the original's `--cli` output.
AString renderText(const SystemSnapshot& snapshot, std::span<const Finding> findings);

/// JSON report {generated, admin, findings, sections, online}. Returns false if the file could not be written.
bool exportReport(const APath& path, const SystemSnapshot& snapshot, std::span<const Finding> findings);

/// "2026-11-22 14:03:05".
AString nowText(AStringView format = "%Y-%m-%d %H:%M:%S");

}   // namespace net
