#include "DBus.h"

#include <AUI/Traits/strings.h>

namespace dbus {

void ConnectionDeleter::operator()(DBusConnection* c) const {
    dbus_connection_close(c);
    dbus_connection_unref(c);
}

Connection sessionBus() {
    dbus_threads_init_default();
    DBusError error;
    dbus_error_init(&error);
    Connection connection(dbus_bus_get_private(DBUS_BUS_SESSION, &error));
    dbus_error_free(&error);
    if (connection) {
        // a lost session bus must not take the application down with it
        dbus_connection_set_exit_on_disconnect(connection.get(), false);
    }
    return connection;
}

Writer& Writer::string(AStringView value) {
    const auto s = std::string(value);
    const char* data = s.c_str();
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_STRING, &data);
    return *this;
}

Writer& Writer::objectPath(AStringView value) {
    const auto s = std::string(value);
    const char* data = s.c_str();
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_OBJECT_PATH, &data);
    return *this;
}

Writer& Writer::int32(int32_t value) {
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_INT32, &value);
    return *this;
}

Writer& Writer::uint32(uint32_t value) {
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_UINT32, &value);
    return *this;
}

Writer& Writer::boolean(bool value) {
    const dbus_bool_t b = value;
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_BOOLEAN, &b);
    return *this;
}

Writer& Writer::byte(uint8_t value) {
    dbus_message_iter_append_basic(&mIter, DBUS_TYPE_BYTE, &value);
    return *this;
}

Writer& Writer::bytes(std::span<const uint8_t> value) {
    return array(DBUS_TYPE_BYTE_AS_STRING, [&](Writer& a) {
        const uint8_t* data = value.data();
        dbus_message_iter_append_fixed_array(&a.mIter, DBUS_TYPE_BYTE, &data, int(value.size()));
    });
}

AOptional<AString> Reader::string() {
    if (auto s = basic<const char*>(DBUS_TYPE_STRING)) {
        return AString(*s);
    }
    return std::nullopt;
}

AOptional<AVector<int32_t>> Reader::int32Array() {
    if (!mValid || dbus_message_iter_get_arg_type(&mIter) != DBUS_TYPE_ARRAY ||
        dbus_message_iter_get_element_type(&mIter) != DBUS_TYPE_INT32) {
        return std::nullopt;
    }
    DBusMessageIter elements;
    dbus_message_iter_recurse(&mIter, &elements);
    const int32_t* data = nullptr;
    int count = 0;
    dbus_message_iter_get_fixed_array(&elements, &data, &count);
    next();
    return AVector<int32_t>(data, data + count);
}

Message methodCall(const char* destination, const char* path, const char* interface, const char* method) {
    return Message(dbus_message_new_method_call(destination, path, interface, method));
}

Message methodReturn(DBusMessage* call) { return Message(dbus_message_new_method_return(call)); }

Message error(DBusMessage* call, const char* name, const char* text) {
    return Message(dbus_message_new_error(call, name, text));
}

Message signal(const char* path, const char* interface, const char* name) {
    return Message(dbus_message_new_signal(path, interface, name));
}

void send(DBusConnection* connection, const Message& message) {
    if (connection && message) {
        dbus_connection_send(connection, message.get(), nullptr);
    }
}

bool isMethod(DBusMessage* message, const char* interface, const char* method) {
    return dbus_message_is_method_call(message, interface, method);
}

namespace {

const Property* find(std::span<const Property> properties, AStringView name) {
    for (const auto& p : properties) {
        if (name == p.name) {
            return &p;
        }
    }
    return nullptr;
}

}   // namespace

Message propertiesReply(DBusMessage* call, const char* interface, std::span<const Property> properties) {
    Reader args(call);
    if (isMethod(call, PROPERTIES, "GetAll")) {
        const auto requested = args.string();
        auto reply = methodReturn(call);
        Writer(reply.get()).array("{sv}", [&](Writer& dict) {
            if (!requested || *requested != interface) {
                return;
            }
            for (const auto& p : properties) {
                dict.entry(p.name, p.signature, p.write);
            }
        });
        return reply;
    }
    if (isMethod(call, PROPERTIES, "Get")) {
        const auto requested = args.string();
        const auto name = args.string();
        if (!requested || *requested != interface || !name) {
            return error(call, DBUS_ERROR_UNKNOWN_INTERFACE, "unknown interface");
        }
        const auto* p = find(properties, *name);
        if (!p) {
            return error(call, DBUS_ERROR_UNKNOWN_PROPERTY, "unknown property");
        }
        auto reply = methodReturn(call);
        Writer(reply.get()).variant(p->signature, p->write);
        return reply;
    }
    if (isMethod(call, PROPERTIES, "Set")) {
        return error(call, DBUS_ERROR_PROPERTY_READ_ONLY, "read-only property");
    }
    return nullptr;
}

AString introspection(const char* interface, std::span<const Property> properties, AStringView members) {
    AString xml = DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE;
    xml += "<node>\n";
    xml += " <interface name=\"{}\">\n"_format(interface);
    for (const auto& p : properties) {
        xml += "  <property name=\"{}\" type=\"{}\" access=\"read\"/>\n"_format(p.name, p.signature);
    }
    xml += members;
    xml += " </interface>\n";
    xml += R"( <interface name="org.freedesktop.DBus.Properties">
  <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="out"/></method>
  <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>
  <method name="Set"><arg type="s" direction="in"/><arg type="s" direction="in"/><arg type="v" direction="in"/></method>
 </interface>
 <interface name="org.freedesktop.DBus.Introspectable">
  <method name="Introspect"><arg type="s" direction="out"/></method>
 </interface>
</node>
)";
    return xml;
}

Export::Export(DBusConnection* connection, const char* path, Handler handler)
  : mConnection(connection), mPath(path), mHandler(std::make_unique<Handler>(std::move(handler))) {
    static const DBusObjectPathVTable VTABLE = {
        .message_function = [](DBusConnection* c, DBusMessage* message, void* data) -> DBusHandlerResult {
            auto reply = (*static_cast<Handler*>(data))(message);
            if (!reply) {
                return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
            }
            dbus_connection_send(c, reply.get(), nullptr);
            return DBUS_HANDLER_RESULT_HANDLED;
        },
    };
    dbus_connection_register_object_path(mConnection, mPath.c_str(), &VTABLE, mHandler.get());
}

Export::~Export() { dbus_connection_unregister_object_path(mConnection, mPath.c_str()); }

}   // namespace dbus
