#pragma once

#include <functional>
#include <memory>
#include <span>
#include <string>

#include <dbus/dbus.h>

#include <AUI/Common/AOptional.h>
#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>

/// Thin RAII and builder layer over libdbus, enough for the tray.
namespace dbus {

struct MessageDeleter {
    void operator()(DBusMessage* m) const { dbus_message_unref(m); }
};
using Message = std::unique_ptr<DBusMessage, MessageDeleter>;

struct ConnectionDeleter {
    void operator()(DBusConnection* c) const;
};
using Connection = std::unique_ptr<DBusConnection, ConnectionDeleter>;

/// Private connection to the session bus; null when there is none.
Connection sessionBus();

/// Appends arguments to a message. Containers take a function that fills them.
class Writer {
public:
    explicit Writer(DBusMessage* message) { dbus_message_iter_init_append(message, &mIter); }

    Writer& string(AStringView value);
    Writer& objectPath(AStringView value);
    Writer& int32(int32_t value);
    Writer& uint32(uint32_t value);
    Writer& boolean(bool value);
    Writer& byte(uint8_t value);
    Writer& bytes(std::span<const uint8_t> value);

    template <typename Fill>
    Writer& array(const char* signature, Fill&& fill) {
        return container(DBUS_TYPE_ARRAY, signature, fill);
    }

    template <typename Fill>
    Writer& structure(Fill&& fill) {
        return container(DBUS_TYPE_STRUCT, nullptr, fill);
    }

    template <typename Fill>
    Writer& variant(const char* signature, Fill&& fill) {
        return container(DBUS_TYPE_VARIANT, signature, fill);
    }

    /// `{sv}` entry of an `a{sv}` dictionary.
    template <typename Fill>
    Writer& entry(AStringView key, const char* signature, Fill&& fill) {
        auto entry = [&](Writer& e) { e.string(key).variant(signature, fill); };
        return container(DBUS_TYPE_DICT_ENTRY, nullptr, entry);
    }

private:
    DBusMessageIter mIter {};

    Writer() = default;

    template <typename Fill>
    Writer& container(int type, const char* signature, Fill& fill) {
        Writer sub;
        dbus_message_iter_open_container(&mIter, type, signature, &sub.mIter);
        fill(sub);
        dbus_message_iter_close_container(&mIter, &sub.mIter);
        return *this;
    }
};

/// Reads arguments one after another; a missing argument or a type mismatch gives nullopt.
class Reader {
public:
    explicit Reader(DBusMessage* message) : mValid(dbus_message_iter_init(message, &mIter)) {}

    AOptional<int32_t> int32() { return basic<int32_t>(DBUS_TYPE_INT32); }
    AOptional<uint32_t> uint32() { return basic<uint32_t>(DBUS_TYPE_UINT32); }
    AOptional<AString> string();
    AOptional<AVector<int32_t>> int32Array();

    /// Calls `read(Reader&)` for every element of an array of structs.
    template <typename Read>
    bool structs(Read&& read) {
        if (!mValid || dbus_message_iter_get_arg_type(&mIter) != DBUS_TYPE_ARRAY) {
            return false;
        }
        DBusMessageIter elements;
        dbus_message_iter_recurse(&mIter, &elements);
        while (dbus_message_iter_get_arg_type(&elements) == DBUS_TYPE_STRUCT) {
            Reader item;
            dbus_message_iter_recurse(&elements, &item.mIter);
            item.mValid = true;
            read(item);
            dbus_message_iter_next(&elements);
        }
        next();
        return true;
    }

    /// Skips one argument of any type.
    void skip() { next(); }

private:
    DBusMessageIter mIter {};
    bool mValid = false;

    Reader() = default;

    void next() { mValid = mValid && dbus_message_iter_next(&mIter); }

    template <typename T>
    AOptional<T> basic(int type) {
        if (!mValid || dbus_message_iter_get_arg_type(&mIter) != type) {
            return std::nullopt;
        }
        T value {};
        dbus_message_iter_get_basic(&mIter, &value);
        next();
        return value;
    }
};

Message methodCall(const char* destination, const char* path, const char* interface, const char* method);
Message methodReturn(DBusMessage* call);
Message error(DBusMessage* call, const char* name, const char* text);
Message signal(const char* path, const char* interface, const char* name);

/// Queues the message; it is written by the thread that dispatches the connection.
void send(DBusConnection* connection, const Message& message);

bool isMethod(DBusMessage* message, const char* interface, const char* method);

/// Read-only property of an exported object.
struct Property {
    const char* name;
    const char* signature;
    std::function<void(Writer&)> write;
};

/// Answers org.freedesktop.DBus.Properties calls for `interface`; null for other methods.
Message propertiesReply(DBusMessage* call, const char* interface, std::span<const Property> properties);

/// Introspection XML of an object with one interface: `members` are its methods and signals, the properties come from
/// the table.
AString introspection(const char* interface, std::span<const Property> properties, AStringView members);

/// An object registered at `path` while this lives. `handler` runs on the dispatching thread and returns the reply, or
/// null for a message it does not handle.
class Export {
public:
    using Handler = std::function<Message(DBusMessage*)>;

    Export(DBusConnection* connection, const char* path, Handler handler);
    ~Export();
    Export(const Export&) = delete;
    Export& operator=(const Export&) = delete;

private:
    DBusConnection* mConnection;
    std::string mPath;
    std::unique_ptr<Handler> mHandler;
};

inline constexpr auto PROPERTIES = DBUS_INTERFACE_PROPERTIES;
inline constexpr auto INTROSPECTABLE = DBUS_INTERFACE_INTROSPECTABLE;

}   // namespace dbus
