#include "ProbeUtil.h"

namespace net::detail {

namespace {

uint16_t randomId() { return uint16_t(std::uniform_int_distribution<int>(0, 0xFFFF)(rng())); }

}   // namespace

std::mt19937& rng() {
    thread_local std::mt19937 engine(std::random_device {}());
    return engine;
}

void put16(AVector<std::byte>& out, uint16_t v) {
    out << std::byte(v >> 8) << std::byte(v & 0xFF);
}

uint16_t get16(std::span<const std::byte> data, size_t off) {
    return uint16_t((std::to_integer<uint16_t>(data[off]) << 8) | std::to_integer<uint16_t>(data[off + 1]));
}

/// DNS A query packet.
AVector<std::byte> dnsQuery(AStringView host) {
    AVector<std::byte> packet;
    put16(packet, randomId());
    put16(packet, 0x0100);   // recursion desired
    put16(packet, 1);
    put16(packet, 0);
    put16(packet, 0);
    put16(packet, 0);
    size_t pos = 0;
    while (pos < host.size()) {
        auto end = host.find('.', pos);
        auto label = host.substr(pos, end == AStringView::npos ? AStringView::npos : end - pos);
        if (!label.empty()) {
            packet << std::byte(label.size());
            for (char c : label) {
                packet << std::byte(c);
            }
        }
        if (end == AStringView::npos) {
            break;
        }
        pos = end + 1;
    }
    packet << std::byte(0);
    put16(packet, 1);   // A
    put16(packet, 1);   // IN
    return packet;
}

AString jsonText(const AJson& object, const AString& key) {
    if (!object.isObject()) {
        return {};
    }
    auto item = object.asObject().contains(key);
    if (!item) {
        return {};
    }
    if (item->second.isString()) {
        return item->second.asString();
    }
    if (item->second.isInt()) {
        return AString::number(item->second.asInt());
    }
    return {};
}

}   // namespace net::detail
