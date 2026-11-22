#include <array>
#include <string>

#include <windows.h>
#include <wincrypt.h>

#include <AUI/Common/AStringVector.h>

#include "Wide.h"
#include "platform/Curl.h"

namespace net::platform {

namespace {

/// Windows root store as PEM, for mbedTLS which has no access to it.
std::string systemRootsPem() {
    std::string pem;
    HCERTSTORE store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) {
        return pem;
    }
    for (PCCERT_CONTEXT cert = nullptr; (cert = CertEnumCertificatesInStore(store, cert));) {
        DWORD size = 0;
        CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, nullptr, &size);
        std::string text(size, '\0');
        if (CryptBinaryToStringA(cert->pbCertEncoded, cert->cbCertEncoded, CRYPT_STRING_BASE64HEADER, text.data(),
                                 &size)) {
            text.resize(size);
            pem += text;
        }
    }
    CertCloseStore(store, 0);
    return pem;
}

}   // namespace

void setupTls(CURL* curl) {
    static const std::string pem = systemRootsPem();
    if (pem.empty()) {
        return;
    }
    curl_blob blob { .data = const_cast<char*>(pem.data()), .len = pem.size(), .flags = CURL_BLOB_NOCOPY };
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &blob);
}

/// WinINET proxy, which urllib on Windows also honours.
AOptional<AString> systemProxy() {
    DWORD enabled = 0;
    DWORD size = sizeof(enabled);
    constexpr auto KEY = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    if (RegGetValueW(HKEY_CURRENT_USER, KEY, L"ProxyEnable", RRF_RT_REG_DWORD, nullptr, &enabled, &size) !=
            ERROR_SUCCESS ||
        !enabled) {
        return std::nullopt;
    }
    std::array<wchar_t, 1024> server {};
    size = sizeof(server);
    if (RegGetValueW(HKEY_CURRENT_USER, KEY, L"ProxyServer", RRF_RT_REG_SZ, nullptr, server.data(), &size) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }
    // "http=host:port;https=host:port" or plain "host:port"
    const AString value = narrow(server.data());
    for (const auto& part : value.split(';')) {
        if (part.startsWith("https=")) {
            return AString(part.substr(6));
        }
    }
    if (value.contains("=")) {
        return AString(value.split(';').first().split('=').last());
    }
    return value;
}

}   // namespace net::platform
