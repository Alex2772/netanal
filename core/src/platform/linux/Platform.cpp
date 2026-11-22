#include <algorithm>

#include "Platform.h"

namespace net::platform {

AStringView osName() { return "Linux"; }

AStringView osTitle() { return "Linux"; }

std::tm localTime(std::time_t time) {
    std::tm local {};
    localtime_r(&time, &local);
    return local;
}

AVector<AString> pingCommand(AStringView host, std::chrono::milliseconds timeout) {
    // -W takes whole seconds
    const auto seconds = std::max<int64_t>(1, std::chrono::duration_cast<std::chrono::seconds>(timeout).count());
    return { "ping", "-c", "1", "-W", AString::number(seconds), AString(host) };
}

}   // namespace net::platform
