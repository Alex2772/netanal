#include "Platform.h"

namespace net::platform {

AStringView osName() { return "Windows"; }

AStringView osTitle() { return "Windows 11"; }

std::tm localTime(std::time_t time) {
    std::tm local {};
    localtime_s(&local, &time);
    return local;
}

AVector<AString> pingCommand(AStringView host, std::chrono::milliseconds timeout) {
    return { "ping", "-n", "1", "-w", AString::number(timeout.count()), AString(host) };
}

}   // namespace net::platform
