#include "Notifications.h"

void notify(DBusConnection* connection, const Notification& notification) {
    auto call = dbus::methodCall("org.freedesktop.Notifications", "/org/freedesktop/Notifications",
                                 "org.freedesktop.Notifications", "Notify");
    dbus::Writer(call.get())
        .string("NetAnal")
        .uint32(0)   // replaces nothing
        .string(notification.icon)
        .string(notification.title)
        .string(notification.body)
        .array("s", [](dbus::Writer&) {})   // no actions
        .array("{sv}", [](dbus::Writer& hints) {
            hints.entry("urgency", "y", [](dbus::Writer& v) { v.byte(1); });   // normal
        })
        .int32(int32_t(notification.timeout.count()));
    dbus_message_set_no_reply(call.get(), true);
    dbus::send(connection, call);
}
