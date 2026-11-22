cmake_minimum_required(VERSION 3.16)
project(netanal
        VERSION 1.0.0 # CI_PROJECT_VERSION
    )

option(BUILD_SHARED_LIBS "Build shared libs" OFF)
option(AUIB_FORCE_PRECOMPILED "AUI.Boot: force precompiled dependencies" OFF)
option(AUIB_NO_PRECOMPILED "AUI.Boot: disable precompiled dependencies" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# MinGW: without this the executables need libwinpthread-1.dll next to them
if (MINGW)
    add_link_options(-static)
endif()

set(AUI_VERSION 7f573c8dc9d14518d3cbacfc2a449bb1073d8d54)

include(aui.boot.cmake)

auib_import(aui https://github.com/aui-framework/aui
        COMPONENTS core views curl json crypt dev_extras
        VERSION ${AUI_VERSION})


# Probing and reporting, shared by the GUI, the CLI and the tests.
add_subdirectory(core)


# GUI
aui_executable(${PROJECT_NAME})
aui_link(${PROJECT_NAME} PRIVATE aui::core aui::views)

if (AUI_PLATFORM_LINUX)
    # tray icon and notifications
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(DBUS REQUIRED IMPORTED_TARGET dbus-1)
    target_link_libraries(${PROJECT_NAME} PRIVATE PkgConfig::DBUS)
endif()
target_link_libraries(${PROJECT_NAME} PRIVATE netanal_core)
aui_compile_assets(${PROJECT_NAME})
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # remote agent for aui-remote; never in release builds
    aui_link(${PROJECT_NAME} PRIVATE aui::dev_extras)
endif()

aui_enable_tests(${PROJECT_NAME})
if (TARGET Tests) # not created when cross-compiling
    target_link_libraries(Tests PRIVATE netanal_core)
endif()

aui_app(TARGET ${PROJECT_NAME}
        NAME "NetAnal"
        VENDOR "NetAnal"
        ICON "assets/img/icon.svg"
)


# Console
add_subdirectory(cli)
