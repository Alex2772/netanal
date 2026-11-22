#pragma once

#include <chrono>
#include <string>
#include <variant>

#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>

/// Running console tools; implemented in platform/<os>/Shell.cpp.
namespace net::platform {

struct ProcessOutput {
    std::string out;
    std::string err;
};

struct ProcessFailure {
    AString message;
};

/// Runs `command` without a shell, kills it after `timeout`.
std::variant<ProcessOutput, ProcessFailure> execute(const AVector<AString>& command,
                                                    std::chrono::milliseconds timeout);

}   // namespace net::platform
