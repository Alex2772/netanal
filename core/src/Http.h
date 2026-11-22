#pragma once

#include <atomic>
#include <variant>

#include "Socket.h"

namespace net {

/// The server answered with any HTTP status, 4xx/5xx included: traffic got through.
struct HttpAnswered {
    long status = 0;
    Ms rtt {};
};

struct HttpFailed {
    AString error;
    /// The server is there, but its certificate does not verify (e.g. the Russian Ministry of Digital Development CA).
    bool sslError = false;
};

using HttpResult = std::variant<HttpAnswered, HttpFailed>;

/// GET `url`, stop after the response headers. With `useSystemProxy` the request goes through the proxy from the
/// environment / Windows settings, otherwise directly.
HttpResult httpTest(AStringView url, bool useSystemProxy, std::chrono::milliseconds timeout);

/// GET `url` and return up to `maxBytes` of the body. Direct, certificate verified.
std::variant<AString, Failure> httpGet(AStringView url, std::chrono::milliseconds timeout, size_t maxBytes = 64 * 1024,
                                       AStringView accept = {});

/// Downloads `url` until `deadline`, adding received bytes to `total`. Direct, like the original's urllib opener.
void download(AStringView url, std::chrono::steady_clock::time_point deadline, std::chrono::milliseconds timeout,
              std::atomic<size_t>& total);

}   // namespace net
