#include "Tray.h"

#include <thread>

#include <unistd.h>

#include <AUI/Logging/ALogger.h>
#include <AUI/Thread/AThread.h>

#include "DBusMenu.h"
#include "Notifications.h"
#include "StatusNotifierItem.h"

namespace {

constexpr auto LOG_TAG = "Tray";

constexpr auto WATCHER = "org.kde.StatusNotifierWatcher";

/// Runs `action` on the UI thread unless the tray is gone by then.
std::function<void()> onUiThread(const _<Tray::Actions>& actions, std::function<void()> Tray::Actions::* action) {
    return [ui = AThread::current(), weak = std::weak_ptr<Tray::Actions>(actions), action] {
        ui->enqueue([weak, action] {
            if (auto a = weak.lock()) {
                ((*a).*action)();
            }
        });
    };
}

/// Asks for org.kde.StatusNotifierItem-<pid>-1 and announces it to the watcher.
bool registerItem(DBusConnection* connection) {
    const AString name = "org.kde.StatusNotifierItem-{}-1"_format(getpid());
    DBusError error;
    dbus_error_init(&error);
    const int owner =
        dbus_bus_request_name(connection, name.toStdString().c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE, &error);
    dbus_error_free(&error);
    if (owner != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        return false;
    }
    auto call = dbus::methodCall(WATCHER, "/StatusNotifierWatcher", WATCHER, "RegisterStatusNotifierItem");
    dbus::Writer(call.get()).string(name);
    dbus_error_init(&error);
    const dbus::Message reply(dbus_connection_send_with_reply_and_block(connection, call.get(), 2000, &error));
    if (!reply) {
        ALogger::warn(LOG_TAG) << "no StatusNotifierWatcher, the window will not hide to the tray: " << error.message;
    }
    dbus_error_free(&error);
    return bool(reply);
}

}   // namespace

struct Tray::Impl {
    _<Actions> actions;
    dbus::Connection connection = dbus::sessionBus();
    std::unique_ptr<DBusMenu> menu;
    std::unique_ptr<StatusNotifierItem> item;
    bool registered = false;
    std::jthread loop;   // last: stops and joins before the objects above go away
};

Tray::Tray(Actions actions) : mImpl(std::make_unique<Impl>()) {
    mImpl->actions = _new<Actions>(std::move(actions));
    const auto connection = mImpl->connection.get();
    if (!connection) {
        ALogger::warn(LOG_TAG) << "no session D-Bus, no tray icon";
        return;
    }
    const auto open = onUiThread(mImpl->actions, &Actions::onOpen);
    mImpl->menu = std::make_unique<DBusMenu>(connection, AVector<DBusMenu::Item> {
                                                             { "Открыть NetAnal", open },
                                                             { "Выйти", onUiThread(mImpl->actions, &Actions::onQuit) },
                                                         });
    mImpl->item = std::make_unique<StatusNotifierItem>(
        connection, StatusNotifierItem::Args { .title = "NetAnal", .menu = DBusMenu::PATH, .onActivate = open });
    mImpl->loop = std::jthread([connection](std::stop_token stop) {
        while (!stop.stop_requested() && dbus_connection_read_write_dispatch(connection, 200)) {
        }
    });
    mImpl->registered = registerItem(connection);
}

Tray::~Tray() = default;

bool Tray::hasIcon() const { return mImpl->registered; }

void Tray::setColor(AColor color) {
    if (mImpl->item) {
        mImpl->item->setColor(color);
    }
}

void Tray::setToolTip(const AString& value) {
    if (mImpl->item) {
        mImpl->item->setToolTip(value);
    }
}

void Tray::showMessage(const AString& title, const AString& message, Kind kind) {
    using namespace std::chrono_literals;
    const bool warning = kind == Kind::WARNING;
    notify(mImpl->connection.get(), Notification {
        .title = title,
        .body = message,
        .icon = warning ? "dialog-warning" : "dialog-information",
        .timeout = warning ? 6000ms : 3000ms,
    });
}
