#include "DBusMenu.h"

namespace {

constexpr int32_t ROOT = 0;

/// The layout never changes.
constexpr uint32_t REVISION = 1;

/// One item of a layout: `(ia{sv}av)`.
constexpr auto LAYOUT_SIGNATURE = "(ia{sv}av)";

constexpr AStringView MEMBERS =
    R"xml(  <method name="GetLayout"><arg type="i" direction="in"/><arg type="i" direction="in"/><arg type="as" direction="in"/><arg type="u" direction="out"/><arg type="(ia{sv}av)" direction="out"/></method>
  <method name="GetGroupProperties"><arg type="ai" direction="in"/><arg type="as" direction="in"/><arg type="a(ia{sv})" direction="out"/></method>
  <method name="GetProperty"><arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
  <method name="Event"><arg type="i" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/><arg type="u" direction="in"/></method>
  <method name="EventGroup"><arg type="a(isvu)" direction="in"/><arg type="ai" direction="out"/></method>
  <method name="AboutToShow"><arg type="i" direction="in"/><arg type="b" direction="out"/></method>
  <method name="AboutToShowGroup"><arg type="ai" direction="in"/><arg type="ai" direction="out"/><arg type="ai" direction="out"/></method>
  <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})"/><arg type="a(ias)"/></signal>
  <signal name="LayoutUpdated"><arg type="u"/><arg type="i"/></signal>
)xml";

}   // namespace

DBusMenu::DBusMenu(DBusConnection* connection, AVector<Item> items)
  : mItems(std::move(items)),
    mProperties {
        { "Version", "u", [](dbus::Writer& w) { w.uint32(3); } },
        { "TextDirection", "s", [](dbus::Writer& w) { w.string("ltr"); } },
        { "Status", "s", [](dbus::Writer& w) { w.string("normal"); } },
        { "IconThemePath", "as", [](dbus::Writer& w) { w.array("s", [](dbus::Writer&) {}); } },
    },
    mExport(connection, PATH, [this](DBusMessage* call) { return handle(call); }) {}

bool DBusMenu::isItem(int32_t id) const { return id >= 1 && size_t(id) <= mItems.size(); }

void DBusMenu::click(int32_t id) {
    if (isItem(id)) {
        mItems[id - 1].onClick();
    }
}

void DBusMenu::writeItemProperties(dbus::Writer& dict, int32_t id) const {
    if (!isItem(id)) {
        dict.entry("children-display", "s", [](dbus::Writer& v) { v.string("submenu"); });
        return;
    }
    dict.entry("label", "s", [&](dbus::Writer& v) { v.string(mItems[id - 1].label); });
    dict.entry("enabled", "b", [](dbus::Writer& v) { v.boolean(true); });
    dict.entry("visible", "b", [](dbus::Writer& v) { v.boolean(true); });
}

void DBusMenu::writeLayout(dbus::Writer& w, int32_t id) const {
    w.structure([&](dbus::Writer& item) {
        item.int32(id);
        item.array("{sv}", [&](dbus::Writer& dict) { writeItemProperties(dict, id); });
        item.array("v", [&](dbus::Writer& children) {
            if (id != ROOT) {
                return;
            }
            for (size_t i = 1; i <= mItems.size(); ++i) {
                children.variant(LAYOUT_SIGNATURE, [&](dbus::Writer& child) { writeLayout(child, int32_t(i)); });
            }
        });
    });
}

dbus::Message DBusMenu::handle(DBusMessage* call) {
    dbus::Reader args(call);
    if (dbus::isMethod(call, INTERFACE, "GetLayout")) {
        const auto parent = args.int32().valueOr(ROOT);
        auto reply = dbus::methodReturn(call);
        dbus::Writer w(reply.get());
        w.uint32(REVISION);
        writeLayout(w, isItem(parent) ? parent : ROOT);
        return reply;
    }
    if (dbus::isMethod(call, INTERFACE, "GetGroupProperties")) {
        auto ids = args.int32Array().valueOr(AVector<int32_t> {});
        if (ids.empty()) {
            for (size_t i = 0; i <= mItems.size(); ++i) {
                ids << int32_t(i);
            }
        }
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).array("(ia{sv})", [&](dbus::Writer& list) {
            for (auto id : ids) {
                list.structure([&](dbus::Writer& item) {
                    item.int32(id).array("{sv}", [&](dbus::Writer& dict) { writeItemProperties(dict, id); });
                });
            }
        });
        return reply;
    }
    if (dbus::isMethod(call, INTERFACE, "GetProperty")) {
        const auto id = args.int32().valueOr(ROOT);
        const auto name = args.string().valueOr("");
        if (!isItem(id) || name != "label") {
            return dbus::error(call, DBUS_ERROR_INVALID_ARGS, "unknown property");
        }
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).variant("s", [&](dbus::Writer& v) { v.string(mItems[id - 1].label); });
        return reply;
    }
    if (dbus::isMethod(call, INTERFACE, "Event")) {
        const auto id = args.int32();
        if (id && args.string().valueOr("") == "clicked") {
            click(*id);
        }
        return dbus::methodReturn(call);
    }
    if (dbus::isMethod(call, INTERFACE, "EventGroup")) {
        args.structs([&](dbus::Reader& event) {
            const auto id = event.int32();
            if (id && event.string().valueOr("") == "clicked") {
                click(*id);
            }
        });
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).array("i", [](dbus::Writer&) {});
        return reply;
    }
    if (dbus::isMethod(call, INTERFACE, "AboutToShow")) {
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).boolean(false);
        return reply;
    }
    if (dbus::isMethod(call, INTERFACE, "AboutToShowGroup")) {
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).array("i", [](dbus::Writer&) {}).array("i", [](dbus::Writer&) {});
        return reply;
    }
    if (dbus::isMethod(call, dbus::INTROSPECTABLE, "Introspect")) {
        auto reply = dbus::methodReturn(call);
        dbus::Writer(reply.get()).string(dbus::introspection(INTERFACE, mProperties, MEMBERS));
        return reply;
    }
    return dbus::propertiesReply(call, INTERFACE, mProperties);
}
