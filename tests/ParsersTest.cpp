#include <gtest/gtest.h>

#include "Parsers.h"
#include "Sites.h"
#include "Verdicts.h"

using namespace net;

TEST(Parsers, RoutePrint) {
    constexpr AStringView TEXT = R"(===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.10     25
          0.0.0.0        128.0.0.0         On-link       10.8.0.2      5
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
===========================================================================
Persistent Routes:
          0.0.0.0          0.0.0.0      192.168.1.1  Default
)";
    const auto routes = parseRoutePrint(TEXT);
    ASSERT_EQ(routes.size(), 3);
    EXPECT_EQ(routes[0], (Route { .network = "0.0.0.0", .mask = "0.0.0.0", .gateway = "192.168.1.1",
                                  .iface = "192.168.1.10", .metric = 25 }));
    EXPECT_TRUE(isOnLink(routes[1]));
    EXPECT_TRUE(isDefaultRoute(routes[0]));
    EXPECT_FALSE(isDefaultRoute(routes[2]));
}

TEST(Parsers, IpconfigAdapters) {
    constexpr AStringView TEXT = R"(Настройка протокола IP для Windows

Адаптер Ethernet Ethernet:

   Описание. . . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   DHCP включен. . . . . . . . . . . : Да
   IPv4-адрес. . . . . . . . . . . . : 192.168.1.10(Основной)
   Основной шлюз. . . . . . . . . : 192.168.1.1
   DNS-серверы. . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8

Неизвестный адаптер AmneziaVPN:

   Состояние среды. . . . . . . . : Среда передачи недоступна.
   Описание. . . . . . . . . . . . . : AmneziaVPN tunnel
)";
    const auto adapters = parseIpconfigAdapters(TEXT);
    ASSERT_EQ(adapters.size(), 2);
    EXPECT_EQ(adapters[0].name, "Ethernet");
    EXPECT_EQ(adapters[0].ipv4, "192.168.1.10");
    EXPECT_EQ(adapters[0].gateway, "192.168.1.1");
    EXPECT_EQ(adapters[0].dhcp, "Да");
    EXPECT_EQ(adapters[0].dns, (AVector<AString> { "1.1.1.1", "8.8.8.8" }));
    EXPECT_FALSE(adapters[0].unknown);
    EXPECT_EQ(adapters[1].name, "AmneziaVPN");
    EXPECT_TRUE(adapters[1].unknown);
    EXPECT_TRUE(isTunnelAdapter(adapters[1]));
    EXPECT_FALSE(isTunnelAdapter(adapters[0]));
}

TEST(Parsers, DisplayDns) {
    constexpr AStringView TEXT = R"(    example.com
    ----------------------------------------
    Имя записи. . . . . . : example.com
    Тип записи. . . . . . : 1
    Запись A (узла) . . . : 93.184.216.34

    Имя записи. . . . . . : blocked.ru
    Запись A (узла) . . . : 127.0.0.1
)";
    const auto records = parseDisplayDns(TEXT);
    ASSERT_EQ(records.size(), 2);
    EXPECT_EQ(records[0], (CacheRecord { .name = "example.com", .ips = { "93.184.216.34" } }));
    EXPECT_TRUE(isSuspiciousCacheIp(records[1].ips.first()));
    EXPECT_FALSE(isSuspiciousCacheIp(records[0].ips.first()));
}

TEST(Parsers, Addresses) {
    EXPECT_EQ(maskToPrefix("255.0.0.0"), 8);
    EXPECT_EQ(maskToPrefix("128.0.0.0"), 1);
    EXPECT_FALSE(maskToPrefix("garbage"));
    EXPECT_TRUE(isTunnelIp("100.64.1.1"));
    EXPECT_TRUE(isTunnelIp("198.19.0.1"));
    EXPECT_TRUE(isTunnelIp("169.254.3.4"));
    EXPECT_FALSE(isTunnelIp("192.168.1.1"));
    EXPECT_FALSE(isTunnelIp("not an ip"));
}

TEST(Parsers, TunnelTrafficFraction) {
    const AVector<Route> routes = {
        { .network = "0.0.0.0", .mask = "128.0.0.0", .gateway = "On-link", .iface = "10.8.0.2", .metric = 5 },
        { .network = "128.0.0.0", .mask = "128.0.0.0", .gateway = "On-link", .iface = "10.8.0.2", .metric = 5 },
        { .network = "224.0.0.0", .mask = "240.0.0.0", .gateway = "On-link", .iface = "10.8.0.2", .metric = 5 },
        { .network = "10.8.0.0", .mask = "255.255.255.0", .gateway = "On-link", .iface = "10.8.0.2", .metric = 5 },
        { .network = "0.0.0.0", .mask = "0.0.0.0", .gateway = "192.168.1.1", .iface = "192.168.1.10", .metric = 25 },
    };
    const auto capture = tunnelTrafficFraction(routes, ASet<AString> { "10.8.0.2" });
    EXPECT_DOUBLE_EQ(capture.fraction, 1.0);
    EXPECT_EQ(capture.routes.size(), 2);
}

TEST(Verdicts, ZoneStatus) {
    EXPECT_EQ(zoneStatus(0, 0).value, "—");
    EXPECT_EQ(zoneStatus(20, 25), (Verdict { "ДОСТУПНО", Severity::OK }));
    EXPECT_EQ(zoneStatus(19, 25), (Verdict { "ЧАСТИЧНО", Severity::WARN }));
    EXPECT_EQ(zoneStatus(12, 25), (Verdict { "НЕДОСТУПНО", Severity::BAD }));
}

TEST(Verdicts, SplitTunneling) {
    const auto status = [](AStringView ru, AStringView foreign, AStringView blocked) {
        PerZone<ZoneIp> zones;
        zones[Zone::RU].ip = AString(ru);
        zones[Zone::FOREIGN].ip = AString(foreign);
        zones[Zone::BLOCKED].ip = AString(blocked);
        return splitTunnelingStatus(zones, true);
    };
    EXPECT_EQ(status("1.1.1.1", "2.2.2.2", "2.2.2.2").severity, Severity::OK);
    EXPECT_EQ(status("1.1.1.1", "1.1.1.1", "2.2.2.2"),
              (Verdict { "Активен (только заблокированные -> 2.2.2.2)", Severity::OK }));
    EXPECT_EQ(status("1.1.1.1", "1.1.1.1", "1.1.1.1").value, "Нет (полный туннель)");
}

TEST(Verdicts, FilteredAvg) {
    EXPECT_FALSE(filteredAvg({}));
    const std::array small = { 10.0, 20.0 };
    EXPECT_DOUBLE_EQ(*filteredAvg(small), 15.0);
    const std::array withOutlier = { 100.0, 102.0, 98.0, 101.0, 99.0, 2000.0 };
    EXPECT_DOUBLE_EQ(*filteredAvg(withOutlier), 100.0);
}

TEST(Verdicts, Severities) {
    EXPECT_EQ(pingSeverity(149), Severity::OK);
    EXPECT_EQ(pingSeverity(200), Severity::WARN);
    EXPECT_EQ(pingSeverity(400), Severity::BAD);
    EXPECT_EQ(speedSeverity(15), Severity::OK);
    EXPECT_EQ(udpSeverity(50, 30), Severity::BAD);
    EXPECT_EQ(udpSeverity(50, 0), Severity::OK);
}

TEST(Sites, Defaults) {
    for (auto zone : ZONES) {
        EXPECT_EQ(defaultSites(zone).size(), 25) << zoneName(zone);
    }
    EXPECT_EQ(hostOf("https://www.gosuslugi.ru/path?q"), "www.gosuslugi.ru");
}
