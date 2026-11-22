#pragma once

#include <string>
#include <string_view>

#include <windows.h>

#include <AUI/Common/AString.h>

namespace net::platform {

/// UTF-8 (or `codepage`) to UTF-16 for the W functions of WinAPI.
inline std::wstring widen(AStringView s, UINT codepage = CP_UTF8) {
    if (s.empty()) {
        return {};
    }
    std::wstring result(MultiByteToWideChar(codepage, 0, s.data(), int(s.size()), nullptr, 0), L'\0');
    MultiByteToWideChar(codepage, 0, s.data(), int(s.size()), result.data(), int(result.size()));
    return result;
}

inline std::string narrow(std::wstring_view s) {
    if (s.empty()) {
        return {};
    }
    std::string result(WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0, nullptr, nullptr), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), int(s.size()), result.data(), int(result.size()), nullptr, nullptr);
    return result;
}

}   // namespace net::platform
