#include <iostream>
#include <ranges>

#include <AUI/Platform/Entry.h>

#include "Console.h"
#include "Match.h"
#include "Online.h"
#include "Report.h"
#include "Shell.h"
#include "System.h"

using namespace net;

namespace {

constexpr auto USAGE = R"(NetAnal — диагностика сети, туннеля и DNS (консольный режим).

Использование: netanal_cli [--cli] [--export[=файл]] [--online]

  --cli               отчёт о сетевой конфигурации (по умолчанию)
  --export[=файл]     сохранить отчёт в JSON (по умолчанию netanal-report.json)
  --online            после отчёта прогнать онлайн-проверку зон из sites.json
  --help              эта справка
)";

AString httpCell(const HttpResult& r) {
    return match(
        r, [](const HttpAnswered& a) { return "{} · {:.0f}мс"_format(a.status, a.rtt.count()); },
        [](const HttpFailed& f) { return f.sslError ? AString("SSL серт (Минцифры?)") : "✗ " + f.error; });
}

void printEvent(const OnlineEvent& event) {
    match(
        event,
        [](const online::SiteChecked& e) {
            const auto& r = e.result;
            const auto dns = match(
                r.dns, [](const Resolved& d) { return join(d.ips, ", "); },
                [](const Failure& f) { return "✗ " + f.error; });
            const auto tcp = match(
                r.tcp, [](Ms ms) { return "ok {:.0f}мс"_format(ms.count()); },
                [](const Failure& f) { return "✗ " + f.error; });
            std::cout << "[{}] {} | {} | {} | {} | {} | {} -> {}\n"_format(zoneName(r.zone), r.name, r.host, dns, tcp,
                                                                        httpCell(r.http), httpCell(r.httpDirect),
                                                                        siteReachable(r) ? "доступен" : "нет");
        },
        [](const online::DnsServerChecked& e) {
            const auto cell = match(
                e.result, [](const DnsAnswer& a) { return "ok {:.1f}мс {}"_format(a.rtt.count(), join(a.ips, ", ")); },
                [](const Failure& f) { return "✗ " + f.error; });
            std::cout << "[DNS] {} | {} | {}\n"_format(e.label, e.server, cell);
        },
        [](const online::GatewayChecked& e) {
            const auto cell = match(
                e.result,
                [](const AOptional<int>& ms) { return ms ? "ok {}мс"_format(*ms) : AString("ok"); },
                [](const Failure& f) { return "✗ " + f.error; });
            std::cout << "[Шлюз] {} | {}\n"_format(e.gateway, cell);
        },
        [](const online::SpeedMeasured& e) {
            const auto cell = match(
                e.result,
                [](const Speed& s) { return "{:.1f} Мбит/с ({} байт за {} с)"_format(s.mbps, s.bytes, s.seconds); },
                [](const Failure& f) { return "✗ " + f.error; });
            std::cout << "[Скорость] {} | {}\n"_format(zoneName(e.zone), cell);
        },
        [](const online::IpsDetected& e) {
            for (auto zone : ZONES) {
                const auto& z = e.zones[zone];
                const auto geo = z.geo ? "{} {} {}"_format(z.geo->country, z.geo->asn, z.geo->org) : AString("—");
                const auto route = [&](const Egress& eg) { return eg.viaTunnel ? "туннель" : "напрямую"; };
                const auto egress = z.egress ? "{} ({})"_format(z.egress->ip, route(*z.egress)) : AString("—");
                std::cout << "[IP] {} | {} | {} | {}\n"_format(zoneName(zone), z.ip.valueOr("—"), geo, egress);
            }
        },
        [](const online::UdpChecked& e) {
            const auto cell = match(
                e.result,
                [](const UdpZoneOk& u) {
                    AVector<AString> ports;
                    for (auto p : u.ports) {
                        ports << AString::number(p);
                    }
                    return "{:.0f} мс · потери {:.0f}% · порты {}"_format(u.rtt, u.loss, join(ports, ", "));
                },
                [](const UdpZoneFailed& f) { return "✗ " + f.error; });
            std::cout << "[UDP] {} | {}\n"_format(zoneName(e.zone), cell);
        },
        [](const online::Done&) { std::cout << "[готово]\n"; });
    std::cout.flush();
}

}   // namespace

AUI_ENTRY {
    setupConsole();
    AOptional<APath> exportPath;
    bool runOnlineCheck = false;
    for (const auto& arg : args | std::views::drop(1)) {   // args[0] is the executable
        if (arg == "--help" || arg == "-h") {
            std::cout << USAGE;
            return 0;
        }
        if (arg == "--online") {
            runOnlineCheck = true;
        } else if (arg.startsWith("--export")) {
            const auto eq = arg.find('=');
            exportPath = APath(eq == AString::NPOS ? AString("netanal-report.json") : AString(arg.substr(eq + 1)));
        } else if (arg != "--cli") {
            std::cerr << "неизвестный аргумент: " << arg << "\n" << USAGE;
            return 2;
        }
    }

    const auto snapshot = collectSystem();
    const auto findings = analyze(snapshot);
    std::cout << renderText(snapshot, findings) << std::endl;
    if (exportPath) {
        if (!exportReport(*exportPath, snapshot, findings)) {
            std::cerr << "\nНе удалось записать " << exportPath->toStdString() << "\n";
            return 1;
        }
        std::cout << "\nОтчёт сохранён: " << exportPath->toStdString() << std::endl;
    }
    if (runOnlineCheck) {
        std::atomic_bool stop = false;
        std::cout << "\n## Онлайн-проверка\n";
        runOnline(loadSiteLists(), printEvent, stop);
    }
    return 0;
}
