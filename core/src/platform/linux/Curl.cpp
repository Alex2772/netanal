#include <array>
#include <filesystem>
#include <string_view>

#include "platform/Curl.h"

namespace net::platform {

namespace {

/// The bundle of the distribution.
AOptional<std::string> caBundlePath() {
    static constexpr auto CANDIDATES = std::to_array<std::string_view>({
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        "/etc/ssl/cert.pem",
    });
    for (auto path : CANDIDATES) {
        if (std::filesystem::exists(path)) {
            return std::string(path);
        }
    }
    return std::nullopt;
}

}   // namespace

void setupTls(CURL* curl) {
    static const auto path = caBundlePath();
    if (path) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, path->c_str());
    }
}

AOptional<AString> systemProxy() { return std::nullopt; }

}   // namespace net::platform
