#pragma once

#include <functional>

#include "DBus.h"

/// com.canonical.dbusmenu: the context menu of a StatusNotifierItem, a flat list of items.
class DBusMenu {
public:
    static constexpr auto PATH = "/MenuBar";
    static constexpr auto INTERFACE = "com.canonical.dbusmenu";

    struct Item {
        AString label;
        /// Runs on the D-Bus thread.
        std::function<void()> onClick;
    };

    DBusMenu(DBusConnection* connection, AVector<Item> items);

private:
    AVector<Item> mItems;
    AVector<dbus::Property> mProperties;
    dbus::Export mExport;   // last: its handler uses the members above

    dbus::Message handle(DBusMessage* call);
    void click(int32_t id);
    [[nodiscard]] bool isItem(int32_t id) const;
    void writeItemProperties(dbus::Writer& dict, int32_t id) const;
    void writeLayout(dbus::Writer& w, int32_t id) const;
};
