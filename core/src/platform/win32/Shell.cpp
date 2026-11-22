#include <array>
#include <thread>

#include <windows.h>
#include <shlobj.h>

#include "Shell.h"
#include "Utf8.h"
#include "Wide.h"
#include "platform/Process.h"

namespace net {

namespace {

using platform::narrow;
using platform::widen;

/// Console tools on a Russian Windows print in the OEM codepage (cp866).
std::string decode(std::string_view raw) {
    if (isValidUtf8(raw)) {
        return std::string(raw);
    }
    return narrow(widen(raw, GetOEMCP()));
}

std::wstring quote(AStringView arg) {
    if (!arg.empty() && arg.find_first_of(" \t\"") == AStringView::npos) {
        return widen(arg);
    }
    std::wstring result = L"\"";
    for (auto c : widen(arg)) {
        if (c == L'"') {
            result += L'\\';
        }
        result += c;
    }
    return result + L"\"";
}

struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    Handle(Handle&& o) noexcept : value(std::exchange(o.value, nullptr)) {}
    Handle& operator=(Handle&& o) noexcept {
        std::swap(value, o.value);
        return *this;
    }
    Handle(const Handle&) = delete;
    ~Handle() {
        if (value && value != INVALID_HANDLE_VALUE) {
            CloseHandle(value);
        }
    }
};

struct Pipe {
    Handle read;
    Handle write;
};

Pipe makePipe() {
    SECURITY_ATTRIBUTES sa { .nLength = sizeof(sa), .lpSecurityDescriptor = nullptr, .bInheritHandle = TRUE };
    HANDLE r = nullptr, w = nullptr;
    CreatePipe(&r, &w, &sa, 0);
    SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
    return { Handle(r), Handle(w) };
}

std::string drain(HANDLE pipe) {
    std::string result;
    std::array<char, 4096> buffer {};
    DWORD n = 0;
    while (ReadFile(pipe, buffer.data(), DWORD(buffer.size()), &n, nullptr) && n > 0) {
        result.append(buffer.data(), n);
    }
    return result;
}

}   // namespace

std::variant<platform::ProcessOutput, platform::ProcessFailure> platform::execute(const AVector<AString>& command,
                                                                                std::chrono::milliseconds timeout) {
    std::wstring cmdline;
    for (const auto& arg : command) {
        if (!cmdline.empty()) {
            cmdline += L' ';
        }
        cmdline += quote(arg);
    }
    auto out = makePipe();
    auto err = makePipe();
    STARTUPINFOW si {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = nullptr;
    si.hStdOutput = out.write.value;
    si.hStdError = err.write.value;
    PROCESS_INFORMATION pi {};
    if (!CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si,
                        &pi)) {
        return ProcessFailure { "[ошибка: не удалось запустить {} (код {})]"_format(command.first(), GetLastError()) };
    }
    Handle process(pi.hProcess);
    Handle thread(pi.hThread);
    out.write = {};
    err.write = {};

    std::string stdOut, stdErr;
    std::thread outReader([&] { stdOut = drain(out.read.value); });
    std::thread errReader([&] { stdErr = drain(err.read.value); });
    const bool finished = WaitForSingleObject(process.value, DWORD(timeout.count())) == WAIT_OBJECT_0;
    if (!finished) {
        TerminateProcess(process.value, 1);
    }
    outReader.join();
    errReader.join();
    if (!finished) {
        return ProcessFailure { "[таймаут]" };
    }
    return ProcessOutput { decode(stdOut), decode(stdErr) };
}

AOptional<AJson> psJson(AStringView command, std::chrono::milliseconds timeout) {
    auto full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; {}"_format(command);
    auto result = platform::execute(
        { "powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full }, timeout);
    auto* output = std::get_if<platform::ProcessOutput>(&result);
    if (!output) {
        return std::nullopt;
    }
    auto text = AString(AString(output->out).trim(" \t\r\n"));
    if (text.empty()) {
        return std::nullopt;
    }
    try {
        return AJson::fromString(text);
    } catch (...) {
        return std::nullopt;
    }
}

bool isAdmin() { return IsUserAnAdmin(); }

}   // namespace net
