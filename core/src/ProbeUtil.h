#pragma once

#include <cmath>
#include <random>
#include <span>

#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>
#include <AUI/Json/AJson.h>

/// Helpers shared by the probe sources.
namespace net::detail {

std::mt19937& rng();

void put16(AVector<std::byte>& out, uint16_t v);

uint16_t get16(std::span<const std::byte> data, size_t off);

/// DNS A query packet.
AVector<std::byte> dnsQuery(AStringView host);

/// String or integer field of a JSON object; empty if there is none.
AString jsonText(const AJson& object, const AString& key);

inline double round1(double v) { return std::round(v * 10) / 10; }

}   // namespace net::detail
