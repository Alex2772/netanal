#include "StatusNotifierItem.h"

#include "Theme.h"
#include "TrayIcon.h"

namespace {

constexpr AStringView MEMBERS = R"(  <method name="Activate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="ContextMenu"><arg type="i" direction="in"/><arg type="i" direction="in"/></method>
  <method name="Scroll"><arg type="i" direction="in"/><arg type="s" direction="in"/></method>
  <signal name="NewTitle"/>
  <signal name="NewIcon"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg type="s"/></signal>
)";

/// ARGB32 in network byte order, as IconPixmap wants it.
AVector<uint8_t> circlePixels(AColor color) {
    AVector<uint8_t> pixels;
    pixels.reserve(tray_icon::SIZE * tray_icon::SIZE * 4);
    const auto channel = [](float c) { return uint8_t(c * 255.f + 0.5f); };
    for (int y = 0; y < tray_icon::SIZE; ++y) {
        for (int x = 0; x < tray_icon::SIZE; ++x) {
            pixels << channel(tray_icon::coverage(x, y)) << channel(color.r) << channel(color.g) << channel(color.b);
        }
    }
    return pixels;
}

/// One image of an `a(iiay)` icon list.
void writePixmap(dbus::Writer& list, AColor color) {
    list.structure([&](dbus::Writer& image) {
        image.int32(tray_icon::SIZE).int32(tray_icon::SIZE).bytes(circlePixels(color));
    });
}

}   // namespace

StatusNotifierItem::StatusNotifierItem(DBusConnection* connection, Args args)
  : mConnection(connection),
    mArgs(std::move(args)),
    mState { .color = theme::MONITOR_OFF, .toolTip = mArgs.title },
    mProperties {
        { "Category", "s", [](dbus::Writer& w) { w.string("ApplicationStatus"); } },
        { "Id", "s", [](dbus::Writer& w) { w.string("netanal"); } },
        { "Title", "s", [this](dbus::Writer& w) { w.string(mArgs.title); } },
        { "Status", "s", [](dbus::Writer& w) { w.string("Active"); } },
        { "WindowId", "u", [](dbus::Writer& w) { w.uint32(0); } },
        { "IconName", "s", [](dbus::Writer& w) { w.string(""); } },
        { "IconPixmap", "a(iiay)",
          [this](dbus::Writer& w) {
              w.array("(iiay)", [&](dbus::Writer& list) { writePixmap(list, state().color); });
          } },
        { "ToolTip", "(sa(iiay)ss)",
          [this](dbus::Writer& w) {
              w.structure([&](dbus::Writer& tip) {
                  tip.string("").array("(iiay)", [](dbus::Writer&) {}).string(state().toolTip).string("");
              });
          } },
        { "ItemIsMenu", "b", [](dbus::Writer& w) { w.boolean(false); } },
        { "Menu", "o", [this](dbus::Writer& w) { w.objectPath(mArgs.menu); } },
    },
    mExport(connection, PATH, [this](DBusMessage* call) { return handle(call); }) {}

void StatusNotifierItem::setColor(AColor color) {
    {
        std::unique_lock lock(mMutex);
        mState.color = color;
    }
    emitSignal("NewIcon");
}

void StatusNotifierItem::setToolTip(AString toolTip) {
    {
        std::unique_lock lock(mMutex);
        mState.toolTip = std::move(toolTip);
    }
    emitSignal("NewToolTip");
}

StatusNotifierItem::State StatusNotifierItem::state() {
    std::unique_lock lock(mMutex);
    return mState;
}

void StatusNotifierItem::emitSignal(const char* signal) {
    dbus::send(mConnection, dbus::signal(PATH, INTERFACE, signal));
}

dbus::Message StatusNotifierItem::handle(DBusMessage* call) {
    if (dbus::isMethod(call, INTERFACE, "Activate") || dbus::isMethod(call, INTERFACE, "SecondaryActivate")) {
        mArgs.onActivate();
        return dbus::methodReturn(call);
    }
    if (dbus::isMethod(call, INTERFACE, "ContextMenu") || dbus::isMethod(call, INTERFACE, "Scroll")) {
        return dbus::methodReturn(call);   // the host shows the dbusmenu itself
    }
    if (dbus::isMethod(call, dbus::INTROSPECTABLE, "Introspect")) {
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).string(dbus::introspection(INTERFACE, mProperties, MEMBERS));
        return reply;
    }
    return dbus::propertiesReply(call, INTERFACE, mProperties);
}
