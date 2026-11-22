#include "Shell.h"

#include <algorithm>

#include "Utf8.h"
#include "platform/Process.h"

namespace net {

AString runRaw(const AVector<AString>& command, std::chrono::milliseconds timeout) {
    if (command.empty()) {
        return {};
    }
    auto result = platform::execute(command, timeout);
    if (auto* failure = std::get_if<platform::ProcessFailure>(&result)) {
        return failure->message;
    }
    auto& [out, err] = std::get<platform::ProcessOutput>(result);
    if (!isValidUtf8(out) || !isValidUtf8(err)) {
        return "[ошибка: вывод не в UTF-8]";
    }
    AString text = std::move(out);
    if (!AString(err).trim().empty()) {
        text += "\n";
        text += err;
    }
    return AString(text.trim(" \t\r\n"));
}

AVector<AString> lines(AStringView text) {
    AVector<AString> result;
    size_t start = 0;
    while (start <= text.size()) {
        auto end = text.find('\n', start);
        if (end == AStringView::npos) {
            end = text.size();
        }
        auto line = text.substr(start, end - start);
        if (line.ends_with('\r')) {
            line.remove_suffix(1);
        }
        result << AString(line);
        start = end + 1;
    }
    return result;
}

bool containsAny(AStringView haystack, std::span<const AStringView> lowercasePatterns) {
    const auto low = AString(haystack).lowercase();
    return std::ranges::any_of(lowercasePatterns, [&](AStringView p) { return low.contains(p); });
}

AString join(std::span<const AString> items, AStringView separator) {
    AString result;
    for (const auto& item : items) {
        if (!result.empty()) {
            result += separator;
        }
        result += item;
    }
    return result;
}

}   // namespace net
