#pragma once

#include <AUI/Common/AString.h>
#include <AUI/Traits/strings.h>

namespace net {

/// Colour class of a verdict shown on a card.
enum class Severity { OK, WARN, BAD, NEUTRAL };

/// A short verdict: "Активен" / "Через туннель" / "Чистый".
struct Verdict {
    AString value;
    Severity severity = Severity::NEUTRAL;

    bool operator==(const Verdict&) const = default;
};

/// Level of a finding on the "Сводка" tab.
enum class Level { ERR, WARN, INFO };

struct Finding {
    Level level;
    AString message;

    bool operator==(const Finding&) const = default;
};

constexpr AStringView levelName(Level level) {
    switch (level) {
        case Level::ERR:
            return "error";
        case Level::WARN:
            return "warn";
        case Level::INFO:
            return "info";
    }
    return {};
}

constexpr AStringView severityName(Severity severity) {
    switch (severity) {
        case Severity::OK:
            return "ok";
        case Severity::WARN:
            return "warn";
        case Severity::BAD:
            return "bad";
        case Severity::NEUTRAL:
            return "neutral";
    }
    return {};
}

}   // namespace net
