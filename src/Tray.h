#pragma once

#include <functional>
#include <memory>

#include <AUI/Common/AColor.h>
#include <AUI/Common/AString.h>

/// System tray icon: a coloured circle with "Открыть NetAnal" / "Выйти" and balloon messages.
/// Windows: Shell_NotifyIcon (platform/win32). Linux: StatusNotifierItem and desktop notifications over D-Bus
/// (platform/linux).
class Tray {
public:
    struct Actions {
        std::function<void()> onOpen;
        std::function<void()> onQuit;
    };

    explicit Tray(Actions actions);
    ~Tray();
    Tray(const Tray&) = delete;
    Tray& operator=(const Tray&) = delete;

    /// Whether the icon exists, so hiding the window keeps the app reachable.
    [[nodiscard]] bool hasIcon() const;

    void setColor(AColor color);
    void setToolTip(const AString& value);

    enum class Kind { INFO, WARNING };
    void showMessage(const AString& title, const AString& message, Kind kind);

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
};
