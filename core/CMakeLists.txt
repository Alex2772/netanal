# Probing and reporting, shared by the GUI, the CLI and the tests. aui_module takes src/ and drops the platform/<os>
# directories of other systems.
aui_module(netanal_core FORCE_STATIC)
aui_link(netanal_core PUBLIC aui::core aui::curl aui::json)
target_compile_options(netanal_core PRIVATE $<$<CXX_COMPILER_FRONTEND_VARIANT:MSVC>:/utf-8>)

# platform/<os>/NativeSocket.h is included as "NativeSocket.h"
if (AUI_PLATFORM_WIN)
    set(NETANAL_PLATFORM win32)
elseif (AUI_PLATFORM_LINUX)
    set(NETANAL_PLATFORM linux)
else ()
    message(FATAL_ERROR "netanal_core: only Windows and Linux are supported")
endif ()
target_include_directories(netanal_core PRIVATE src/platform/${NETANAL_PLATFORM})
