#include <AUI/Json/AJson.h>

#include "Http.h"
#include "ProbeUtil.h"
#include "Probes.h"
#include "Socket.h"

namespace net {

using namespace detail;

namespace {

size_t skipName(std::span<const std::byte> data, size_t off) {
    while (off < data.size()) {
        const auto length = std::to_integer<uint8_t>(data[off]);
        if (length == 0) {
            return off + 1;
        }
        if ((length & 0xC0) == 0xC0) {
            return off + 2;
        }
        off += 1 + length;
    }
    return data.size();
}

AVector<AString> parseA(std::span<const std::byte> data, int questions, int answers) {
    AVector<AString> ips;
    size_t off = 12;
    for (int i = 0; i < questions; ++i) {
        off = skipName(data, off) + 4;
    }
    for (int i = 0; i < answers && off + 10 <= data.size(); ++i) {
        off = skipName(data, off);
        if (off + 10 > data.size()) {
            break;
        }
        const auto type = get16(data, off);
        const auto length = get16(data, off + 8);
        off += 10;
        if (off + length > data.size()) {
            break;
        }
        if (type == 1 && length == 4) {
            ips << "{}.{}.{}.{}"_format(std::to_integer<int>(data[off]), std::to_integer<int>(data[off + 1]),
                                        std::to_integer<int>(data[off + 2]), std::to_integer<int>(data[off + 3]));
        }
        off += length;
    }
    return ips;
}

}   // namespace

std::variant<DnsAnswer, Failure> dnsUdpQuery(AStringView server, AStringView host, std::chrono::milliseconds timeout) {
    const auto packet = dnsQuery(host);
    auto reply = udpExchange(server, 53, packet, timeout);
    if (auto* failure = std::get_if<Failure>(&reply)) {
        return *failure;
    }
    const auto& [data, rtt] = std::get<UdpReply>(reply);
    if (data.size() < 12) {
        return Failure { "короткий ответ" };
    }
    const auto flags = get16(data, 2);
    const int questions = get16(data, 4);
    const int answers = get16(data, 6);
    return DnsAnswer { .rtt = Ms(round1(rtt.count())),
                       .rcode = flags & 0x000F,
                       .answers = answers,
                       .ips = parseA(data, questions, answers) };
}

std::variant<AVector<AString>, Failure> dohQuery(AStringView domain, AStringView server,
                                                 std::chrono::milliseconds timeout) {
    auto body = httpGet("https://{}/dns-query?name={}&type=A"_format(server, domain), timeout, 64 * 1024,
                        "application/dns-json");
    if (auto* failure = std::get_if<Failure>(&body)) {
        return *failure;
    }
    try {
        const auto json = AJson::fromString(std::get<AString>(body));
        AVector<AString> ips;
        if (auto answer = json.asObject().contains("Answer"); answer && answer->second.isArray()) {
            for (const auto& a : answer->second.asArray()) {
                if (jsonText(a, "type") == "1") {
                    ips << jsonText(a, "data");
                }
            }
        }
        return ips;
    } catch (const AException& e) {
        return Failure { e.getMessage() };
    }
}

}   // namespace net
