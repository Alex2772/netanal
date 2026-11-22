#pragma once

#include <curl/curl.h>

#include <AUI/Common/AOptional.h>
#include <AUI/Common/AString.h>

/// What curl needs from the system; implemented in platform/<os>/Curl.cpp.
namespace net::platform {

/// Points curl at the system root certificates: the bundled mbedTLS does not find them on its own.
void setupTls(CURL* curl);

/// The proxy the system is configured with; nullopt lets curl read the environment.
AOptional<AString> systemProxy();

}   // namespace net::platform
