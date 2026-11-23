#include "Http.h"

#include <array>
#include <memory>

#include <AUI/Traits/strings.h>

#include <curl/curl.h>

#include "platform/Curl.h"

namespace net {

namespace {

using Clock = std::chrono::steady_clock;

constexpr auto USER_AGENT = "NetAnal/1.0";

struct CurlGlobal {
    CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
};

struct EasyDeleter {
    void operator()(CURL* c) const { curl_easy_cleanup(c); }
};
using Easy = std::unique_ptr<CURL, EasyDeleter>;

struct SlistDeleter {
    void operator()(curl_slist* l) const { curl_slist_free_all(l); }
};
using Slist = std::unique_ptr<curl_slist, SlistDeleter>;

void setupProxy(CURL* c, bool useSystemProxy) {
    if (!useSystemProxy) {
        curl_easy_setopt(c, CURLOPT_PROXY, "");
        return;
    }
    // without a system proxy curl reads http_proxy / https_proxy / all_proxy itself
    if (auto proxy = platform::systemProxy()) {
        curl_easy_setopt(c, CURLOPT_PROXY, proxy->toStdString().c_str());
    }
}

Easy makeEasy(AStringView url, bool useSystemProxy, std::chrono::milliseconds timeout) {
    static CurlGlobal global;
    Easy c(curl_easy_init());
    curl_easy_setopt(c.get(), CURLOPT_URL, std::string(url).c_str());
    curl_easy_setopt(c.get(), CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(c.get(), CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c.get(), CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c.get(), CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(c.get(), CURLOPT_CONNECTTIMEOUT_MS, long(timeout.count()));
    platform::setupTls(c.get());
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    setupProxy(c.get(), useSystemProxy);
    return c;
}

AString errorText(CURLcode code, const std::array<char, CURL_ERROR_SIZE>& buffer) {
    if (buffer.front() != '\0') {
        return AString(buffer.data());
    }
    return AString(curl_easy_strerror(code));
}

}   // namespace

HttpResult httpTest(AStringView url, bool useSystemProxy, std::chrono::milliseconds timeout) {
    auto c = makeEasy(url, useSystemProxy, timeout);
    std::array<char, CURL_ERROR_SIZE> error {};
    curl_easy_setopt(c.get(), CURLOPT_ERRORBUFFER, error.data());
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT_MS, long(timeout.count() * 2));
    // headers are enough: abort on the first byte of the body
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, +[](char*, size_t, size_t, void*) -> size_t { return 0; });

    const auto start = Clock::now();
    const auto code = curl_easy_perform(c.get());
    const auto rtt = std::chrono::duration_cast<Ms>(Clock::now() - start);
    long status = 0;
    curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &status);
    if (status > 0 && (code == CURLE_OK || code == CURLE_WRITE_ERROR || code == CURLE_TOO_MANY_REDIRECTS)) {
        return HttpAnswered { .status = status, .rtt = rtt };
    }
    auto text = errorText(code, error);
    // mbedTLS rejects some certificates (e.g. the Russian Trusted Root CA chain) while parsing, before verification
    const bool sslError =
        code == CURLE_PEER_FAILED_VERIFICATION || (code == CURLE_SSL_CONNECT_ERROR && text.contains("X509"));
    return HttpFailed { .error = std::move(text), .sslError = sslError };
}

std::variant<AString, Failure> httpGet(AStringView url, std::chrono::milliseconds timeout, size_t maxBytes,
                                       AStringView accept) {
    auto c = makeEasy(url, true, timeout);
    std::array<char, CURL_ERROR_SIZE> error {};
    curl_easy_setopt(c.get(), CURLOPT_ERRORBUFFER, error.data());
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT_MS, long(timeout.count()));
    Slist headers;
    if (!accept.empty()) {
        headers.reset(curl_slist_append(nullptr, "Accept: {}"_format(accept).toStdString().c_str()));
        curl_easy_setopt(c.get(), CURLOPT_HTTPHEADER, headers.get());
    }
    struct Sink {
        std::string body;
        size_t limit;
    } sink { .body = {}, .limit = maxBytes };
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, +[](char* data, size_t size, size_t n, void* user) -> size_t {
        auto& s = *static_cast<Sink*>(user);
        const auto bytes = size * n;
        s.body.append(data, std::min(bytes, s.limit - std::min(s.limit, s.body.size())));
        return s.body.size() >= s.limit ? 0 : bytes;
    });
    const auto code = curl_easy_perform(c.get());
    long status = 0;
    curl_easy_getinfo(c.get(), CURLINFO_RESPONSE_CODE, &status);
    if (code != CURLE_OK && !(code == CURLE_WRITE_ERROR && sink.body.size() >= maxBytes)) {
        return Failure { errorText(code, error) };
    }
    if (status >= 400) {
        return Failure { "HTTP {}"_format(status) };
    }
    return AString(std::move(sink.body));
}

void download(AStringView url, std::chrono::steady_clock::time_point deadline, std::chrono::milliseconds timeout,
              std::atomic<size_t>& total) {
    auto c = makeEasy(url, true, timeout);
    struct Sink {
        std::atomic<size_t>& total;
        Clock::time_point deadline;
    } sink { .total = total, .deadline = deadline };
    curl_easy_setopt(c.get(), CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(c.get(), CURLOPT_WRITEFUNCTION, +[](char*, size_t size, size_t n, void* user) -> size_t {
        auto& s = *static_cast<Sink*>(user);
        if (Clock::now() >= s.deadline) {
            return 0;
        }
        s.total += size * n;
        return size * n;
    });
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
    curl_easy_setopt(c.get(), CURLOPT_TIMEOUT_MS, long(std::max<int64_t>(left.count(), 1)));
    curl_easy_perform(c.get());
}

}   // namespace net
