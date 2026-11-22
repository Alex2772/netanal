#include "Probes.h"

#include <algorithm>
#include <future>
#include <memory>
#include <regex>
#include <thread>

#include "Http.h"
#include "Platform.h"
#include "ProbeUtil.h"
#include "Shell.h"
#include "Socket.h"

namespace net {

using namespace detail;

namespace {

using Clock = std::chrono::steady_clock;

std::variant<Speed, Failure> speedOnce(AStringView url, std::chrono::milliseconds duration, int workers,
                                       std::chrono::milliseconds timeout) {
    std::atomic<size_t> total = 0;
    const auto start = Clock::now();
    const auto deadline = start + duration;
    {
        AVector<std::jthread> threads;
        for (int i = 0; i < workers; ++i) {
            threads << std::jthread([&] { download(url, deadline, timeout, total); });
        }
    }
    const double seconds = std::chrono::duration<double>(Clock::now() - start).count();
    const size_t bytes = total;
    if (seconds <= 0 || bytes < 500'000) {
        return Failure { "мало данных" };
    }
    return Speed { .mbps = round1(double(bytes) * 8 / (seconds * 1'000'000)),
                   .bytes = bytes,
                   .seconds = std::round(seconds * 100) / 100 };
}

}   // namespace

AVector<AStringView> speedEndpoints(Zone zone) {
    if (zone == Zone::RU) {
        return { "https://mirror.yandex.ru/ubuntu/dists/jammy/Contents-amd64.gz" };
    }
    return { "https://cachefly.cachefly.net/100mb.test", "https://proof.ovh.net/files/100Mb.dat" };
}

AVector<AStringView> echoServers(Zone zone) {
    switch (zone) {
        case Zone::RU:
            return { "https://ip.mail.ru/", "https://check-host.net/ip" };
        case Zone::FOREIGN:
            return { "https://api.ipify.org?format=json", "https://ifconfig.me/ip" };
        case Zone::BLOCKED:
            // ipify is not blocked, so a VPN that tunnels only blocked resources sends it directly. Cloudflare's trace
            // on blocked sites follows the same path as the sites themselves.
            return { "https://meduza.io/cdn-cgi/trace", "https://signal.org/cdn-cgi/trace",
                     "https://medium.com/cdn-cgi/trace" };
    }
    return {};
}

AStringView zoneProbeHost(Zone zone) {
    switch (zone) {
        case Zone::RU:
            return "ya.ru";
        case Zone::FOREIGN:
            return "cloudflare.com";
        case Zone::BLOCKED:
            return "instagram.com";
    }
    return {};
}

std::variant<Resolved, Failure> resolveHost(AStringView host, std::chrono::milliseconds timeout) {
    auto promise = std::make_shared<std::promise<std::variant<AVector<AString>, Failure>>>();
    auto future = promise->get_future();
    const auto start = Clock::now();
    std::thread([promise, host = AString(host)] { promise->set_value(resolveAll(host)); }).detach();
    if (future.wait_for(timeout) != std::future_status::ready) {
        return Failure { "DNS таймаут" };
    }
    auto result = future.get();
    if (auto* failure = std::get_if<Failure>(&result)) {
        return *failure;
    }
    return Resolved { .ips = std::get<AVector<AString>>(std::move(result)),
                      .rtt = std::chrono::duration_cast<Ms>(Clock::now() - start) };
}

std::variant<Ms, Failure> tcpTest(AStringView host, uint16_t port, AOptional<AString> ip,
                                  std::chrono::milliseconds timeout) {
    auto result = tcpConnect(ip ? AStringView(*ip) : host, port, timeout);
    if (auto* failure = std::get_if<Failure>(&result)) {
        return *failure;
    }
    return std::get<TcpConnected>(result).rtt;
}

std::variant<AOptional<int>, Failure> pingTest(AStringView host, std::chrono::milliseconds timeout) {
    const auto out = runRaw(platform::pingCommand(host, timeout), timeout + 2s).toStdString();
    static const std::regex TIME(R"(время[=<]\s*(\d+)\s*мс|time[=<]\s*(\d+)(?:\.\d+)?\s*ms)", std::regex::icase);
    std::smatch m;
    if (std::regex_search(out, m, TIME)) {
        return AOptional<int>(std::stoi(m[1].matched ? m[1].str() : m[2].str()));
    }
    if (std::regex_search(out, std::regex("TTL=|ttl=", std::regex::icase))) {
        return AOptional<int>();
    }
    return Failure { "нет ответа" };
}

std::variant<Speed, Failure> speedTest(std::span<const AStringView> urls, std::chrono::milliseconds duration,
                                       int workers, std::chrono::milliseconds timeout) {
    std::variant<Speed, Failure> last = Failure { "нет URL" };
    for (auto url : urls) {
        last = speedOnce(url, duration, workers, timeout);
        if (std::holds_alternative<Speed>(last)) {
            break;
        }
    }
    return last;
}

SiteResult runSiteTest(Zone zone, const Site& site, std::chrono::milliseconds timeout) {
    const auto host = hostOf(site.url);
    auto dns = resolveHost(host, timeout);
    if (auto* failure = std::get_if<Failure>(&dns)) {
        // DNS did not answer: nothing more to test for this site
        return { .zone = zone,
                 .name = site.name,
                 .host = host,
                 .url = site.url,
                 .dns = dns,
                 .tcp = *failure,
                 .http = HttpFailed { .error = failure->error },
                 .httpDirect = HttpFailed { .error = failure->error } };
    }
    // IPv4 for an honest TCP ping without a second DNS lookup
    const auto& ips = std::get<Resolved>(dns).ips;
    AOptional<AString> ip;
    if (auto it = std::ranges::find_if(ips, [](const AString& i) { return !i.contains(":"); }); it != ips.end()) {
        ip = *it;
    }
    return { .zone = zone,
             .name = site.name,
             .host = host,
             .url = site.url,
             .dns = dns,
             .tcp = tcpTest(host, 443, ip, std::min<std::chrono::milliseconds>(timeout, 3500ms)),
             .http = httpTest(site.url, true, timeout),
             .httpDirect = httpTest(site.url, false, timeout) };
}

}   // namespace net
