#pragma once

#include <chrono>
#include <ctime>

#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>

/// Small differences between Windows and Linux; implemented in platform/<os>/Platform.cpp.
namespace net::platform {

/// "Windows" / "Linux", for the report header.
AStringView osName();

/// "Windows 11" / "Linux", for the window title.
AStringView osTitle();

std::tm localTime(std::time_t time);

/// One ICMP echo with the given reply timeout.
AVector<AString> pingCommand(AStringView host, std::chrono::milliseconds timeout);

}   // namespace net::platform
