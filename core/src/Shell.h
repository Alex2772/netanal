#pragma once

#include <chrono>
#include <span>

#include <AUI/Common/AOptional.h>
#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>
#include <AUI/Traits/strings.h>
#include <AUI/Json/AJson.h>

namespace net {

using namespace std::chrono_literals;

/// Runs a system command without a console window and returns stdout followed by stderr, decoded to UTF-8 and
/// trimmed. Never throws: failures come back as "[таймаут]" or "[ошибка: ...]", like in the original.
AString runRaw(const AVector<AString>& command, std::chrono::milliseconds timeout = 20s);

/// Runs a PowerShell command and parses its JSON output. Windows only; empty elsewhere.
AOptional<AJson> psJson(AStringView command, std::chrono::milliseconds timeout = 40s);

/// Elevated (administrator / root).
bool isAdmin();

/// Lines of `text` without trailing '\r'.
AVector<AString> lines(AStringView text);

/// Case-insensitive substring test against a list of lowercase patterns.
bool containsAny(AStringView haystack, std::span<const AStringView> lowercasePatterns);

AString join(std::span<const AString> items, AStringView separator);

}   // namespace net
