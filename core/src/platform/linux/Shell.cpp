#include <array>
#include <csignal>
#include <cstring>

#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "Shell.h"
#include "platform/Process.h"

extern char** environ;

namespace net {

namespace {

/// Closes the descriptor when it goes out of scope.
struct Fd {
    int value = -1;
    explicit Fd(int fd) : value(fd) {}
    Fd(Fd&& o) noexcept : value(std::exchange(o.value, -1)) {}
    Fd(const Fd&) = delete;
    ~Fd() { reset(); }
    void reset() {
        if (value >= 0) {
            close(std::exchange(value, -1));
        }
    }
};

struct PipeFds {
    Fd read;
    Fd write;
};

AOptional<PipeFds> makePipe() {
    std::array<int, 2> fds {};
    if (pipe(fds.data()) != 0) {
        return std::nullopt;
    }
    return PipeFds { Fd(fds[0]), Fd(fds[1]) };
}

/// NULL-terminated array of C strings over `storage`, for the exec family.
AVector<char*> cStrings(AVector<std::string>& storage) {
    AVector<char*> result;
    for (auto& s : storage) {
        result << s.data();
    }
    result << nullptr;
    return result;
}

/// LC_ALL=C: stable English output of ip/ss/resolvectl regardless of the user's locale.
AVector<std::string> environmentC() {
    AVector<std::string> result { "LC_ALL=C" };
    for (auto e = environ; *e; ++e) {
        if (!std::string_view(*e).starts_with("LC_ALL=")) {
            result << *e;
        }
    }
    return result;
}

struct Spawned {
    pid_t pid;
};

std::variant<Spawned, platform::ProcessFailure> spawn(const AVector<AString>& command, const PipeFds& out,
                                                      const PipeFds& err) {
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, out.write.value, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err.write.value, STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, out.read.value);
    posix_spawn_file_actions_addclose(&actions, err.read.value);

    AVector<std::string> args(command.begin(), command.end());
    auto argv = cStrings(args);
    auto env = environmentC();
    auto envp = cStrings(env);

    pid_t pid = 0;
    const int rc = posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) {
        return platform::ProcessFailure { "[ошибка: {}: {}]"_format(command.first(), strerror(rc)) };
    }
    return Spawned { pid };
}

struct Drained {
    platform::ProcessOutput output;
    bool timedOut = false;
};

/// Reads both pipes until they close or the deadline passes.
Drained drain(Fd outRead, Fd errRead, std::chrono::steady_clock::time_point deadline) {
    Drained result;
    std::array fds = { pollfd { outRead.value, POLLIN, 0 }, pollfd { errRead.value, POLLIN, 0 } };
    size_t open = fds.size();
    std::array<char, 4096> buffer {};
    while (open > 0) {
        const auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            result.timedOut = true;
            break;
        }
        if (poll(fds.data(), fds.size(), int(left.count())) <= 0) {
            continue;
        }
        for (size_t i = 0; i < fds.size(); ++i) {
            if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) {
                continue;
            }
            const auto n = read(fds[i].fd, buffer.data(), buffer.size());
            if (n <= 0) {
                fds[i].fd = -1;   // poll skips negative descriptors
                --open;
                continue;
            }
            (i == 0 ? result.output.out : result.output.err).append(buffer.data(), n);
        }
    }
    return result;
}

}   // namespace

std::variant<platform::ProcessOutput, platform::ProcessFailure> platform::execute(const AVector<AString>& command,
                                                                                std::chrono::milliseconds timeout) {
    auto out = makePipe();
    auto err = makePipe();
    if (!out || !err) {
        return ProcessFailure { "[ошибка: pipe]" };
    }
    auto spawned = spawn(command, *out, *err);
    out->write.reset();
    err->write.reset();
    if (auto* failure = std::get_if<ProcessFailure>(&spawned)) {
        return *failure;
    }
    const auto pid = std::get<Spawned>(spawned).pid;
    auto [output, timedOut] =
        drain(std::move(out->read), std::move(err->read), std::chrono::steady_clock::now() + timeout);
    if (timedOut) {
        kill(pid, SIGKILL);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (timedOut) {
        return ProcessFailure { "[таймаут]" };
    }
    return std::move(output);
}

AOptional<AJson> psJson(AStringView, std::chrono::milliseconds) { return std::nullopt; }

bool isAdmin() { return geteuid() == 0; }

}   // namespace net
