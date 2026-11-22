#pragma once

#include <chrono>

#include "DBus.h"

/// org.freedesktop.Notifications: a desktop notification; does not wait for the reply.
struct Notification {
    AString title;
    AString body;
    /// Freedesktop icon name.
    AStringView icon;
    std::chrono::milliseconds timeout;
};

void notify(DBusConnection* connection, const Notification& notification);
