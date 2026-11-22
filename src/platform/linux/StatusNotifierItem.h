#pragma once

#include <functional>
#include <mutex>

#include <AUI/Common/AColor.h>

#include "DBus.h"

/// org.kde.StatusNotifierItem: the tray icon of KDE, GNOME (AppIndicator extension), XFCE and others.
class StatusNotifierItem {
public:
    static constexpr auto PATH = "/StatusNotifierItem";
    static constexpr auto INTERFACE = "org.kde.StatusNotifierItem";

    struct Args {
        AString title;
        /// Object path of the com.canonical.dbusmenu menu.
        const char* menu;
        /// Click on the icon; runs on the D-Bus thread.
        std::function<void()> onActivate;
    };

    StatusNotifierItem(DBusConnection* connection, Args args);

    void setColor(AColor color);
    void setToolTip(AString toolTip);

private:
    struct State {
        AColor color;
        AString toolTip;
    };

    DBusConnection* mConnection;
    Args mArgs;
    std::mutex mMutex;
    State mState;
    AVector<dbus::Property> mProperties;
    dbus::Export mExport;   // last: its handler uses the members above

    [[nodiscard]] State state();
    void emitSignal(const char* signal);
    dbus::Message handle(DBusMessage* call);
};
