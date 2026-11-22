#include <AUI/Platform/Entry.h>

#if AUI_DEBUG && __has_include(<AUI/Remote/ARemoteDebug.h>)
#include <AUI/Remote/ARemoteDebug.h>
#define netanal_REMOTE_DEBUG 1
#endif

#include "MainWindow.h"

AUI_ENTRY {
#if netanal_REMOTE_DEBUG
    // waits for aui-remote on a loopback port
    auto debug = ARemoteDebug::start(ARemoteDebug::Options::fromEnvironment());
#endif
    _new<MainWindow>()->show();
    return 0;
}
