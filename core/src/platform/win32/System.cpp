#include <algorithm>
#include <cstdlib>
#include <ranges>
#include <regex>

#include <AUI/Common/AMap.h>

#include <windows.h>

#include <AUI/Common/AByteBuffer.h>
#include <AUI/IO/AFileInputStream.h>

#include "Shell.h"
#include "System.h"
#include "Wide.h"

namespace net {

namespace {

constexpr AStringView HOSTS_PATH = R"(C:\Windows\System32\drivers\etc\hosts)";

const AMap<AString, AString> SERVICE_STATUS_NAMES = {
    { "1", "Остановлена" }, { "2", "Запускается" },        { "3", "Останавливается" }, { "4", "Работает" },
    { "5", "Продолжается" }, { "6", "Приостанавливается" }, { "7", "Приостановлена" },
};
const AMap<AString, AString> SERVICE_START_NAMES = {
    { "0", "Загрузка" }, { "1", "Система" }, { "2", "Авто" }, { "3", "Вручную" }, { "4", "Отключена" },
};
const AMap<AString, AString> FIREWALL_PROFILE = {
    { "Domain", "Домен" }, { "Private", "Частная" }, { "Public", "Общедоступная" }, { "Any", "Любой" },
};
const AMap<AString, AString> FIREWALL_ACTION = {
    { "Allow", "Разрешить" }, { "Block", "Блокировать" }, { "NotConfigured", "Не настроено" },
};
const AMap<AString, AString> FIREWALL_DIRECTION = { { "Inbound", "Входящее" }, { "Outbound", "Исходящее" } };
const AMap<AString, AString> FIREWALL_ENABLED = { { "True", "Да" }, { "False", "Нет" } };

/// Value or comma-separated list translated by the dictionary.
AString translate(const AString& value, const AMap<AString, AString>& mapping) {
    AString result;
    for (const auto& part : value.split(',')) {
        auto key = AString(part.trim());
        if (key.empty()) {
            continue;
        }
        if (!result.empty()) {
            result += ", ";
        }
        auto it = mapping.find(key);
        result += it != mapping.end() ? it->second : key;
    }
    return result;
}

/// JSON value as text, the way Python's str() would show it.
AString str(const AJson& json) {
    if (json.isString()) {
        return json.asString();
    }
    if (json.isBool()) {
        return json.asBool() ? "True" : "False";
    }
    if (json.isInt()) {
        return AString::number(json.asInt());
    }
    if (json.isNumber()) {
        return AString::number(json.asNumber());
    }
    if (json.isNull() || json.isEmpty()) {
        return "";
    }
    return AJson::toString(json);
}

AString field(const AJson& object, const AString& key) {
    if (!object.isObject()) {
        return {};
    }
    if (auto item = object.asObject().contains(key)) {
        return str(item->second);
    }
    return {};
}

/// ConvertTo-Json returns an object for one item and an array for many.
AVector<AJson> items(const AOptional<AJson>& json) {
    if (!json) {
        return {};
    }
    if (json->isArray()) {
        return AVector<AJson>(json->asArray().begin(), json->asArray().end());
    }
    return { *json };
}

AOptional<AString> registryValue(HKEY root, AStringView path, AStringView name) {
    DWORD type = 0;
    DWORD size = 0;
    const auto wpath = platform::widen(path);
    const auto wname = platform::widen(name);
    if (RegGetValueW(root, wpath.c_str(), wname.c_str(), RRF_RT_REG_SZ | RRF_RT_REG_DWORD, &type, nullptr, &size) !=
        ERROR_SUCCESS) {
        return std::nullopt;
    }
    AVector<std::byte> buffer(size);
    if (RegGetValueW(root, wpath.c_str(), wname.c_str(), RRF_RT_REG_SZ | RRF_RT_REG_DWORD, &type, buffer.data(),
                     &size) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    if (type == REG_DWORD) {
        return AString::number(*reinterpret_cast<const DWORD*>(buffer.data()));
    }
    return platform::narrow(reinterpret_cast<const wchar_t*>(buffer.data()));
}

Section collectAdapters(const NetworkState& network) {
    Table table { .name = "Сетевые адаптеры (ipconfig /all)",
                  .columns = { "Имя", "Описание", "IPv4", "Шлюз", "DNS", "Состояние", "DHCP" } };
    for (const auto& a : network.adapters) {
        table.rows << AVector<AString> { a.name, a.desc, a.ipv4, a.gateway, join(a.dns, ", "), a.status,
                                         a.dhcp };
    }
    return { .title = "Адаптеры",
             .tables = { std::move(table) },
             .text = network.adaptersText.empty() ? "[ipconfig /all: пусто]" : network.adaptersText };
}

Section collectDns(SystemSnapshot& snapshot) {
    Section section { .title = "DNS" };
    if (auto g = psJson("Get-DnsClientGlobalSetting | ConvertTo-Json -Compress")) {
        Table global { .name = "Глобальные настройки DNS-клиента", .columns = { "Параметр", "Значение" } };
        for (AString key : { "UseSuffixSearchList", "SuffixSearchList", "DevolutionLevel", "UseDevolution" }) {
            global.rows << AVector<AString> { key, field(*g, key) };
        }
        section.tables << std::move(global);
        Table doh { .name = "DNS over HTTPS (DoH)", .columns = { "Параметр", "Значение" } };
        if (g->isObject()) {
            if (auto d = g->asObject().contains("Doh"); d && d->second.isObject()) {
                for (const auto& [k, v] : d->second.asObject()) {
                    doh.rows << AVector<AString> { k, str(v) };
                }
            }
        }
        if (doh.rows.empty()) {
            doh.rows << AVector<AString> { "—", "не задан" };
        }
        section.tables << std::move(doh);
    }

    Table nrpt { .name = "Политики разрешения имён (NRPT — часто ломают обходчики)",
                 .columns = { "Namespace", "NameServers", "Имя", "Secure" } };
    for (const auto& n : items(psJson("Get-DnsClientNrptPolicy | ConvertTo-Json -Compress"))) {
        nrpt.rows << AVector<AString> { field(n, "Namespace"), field(n, "NameServers"), field(n, "DisplayName"),
                                        field(n, "Secure") };
    }
    snapshot.nrptPolicies = nrpt.rows.size();
    if (nrpt.rows.empty()) {
        nrpt.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(nrpt);

    // the resolver cache: exactly what 'ipconfig /flushdns' clears
    const auto raw = runRaw({ "ipconfig", "/displaydns" });
    static const std::regex ELEVATION("elevation|повышени|администратор", std::regex::icase);
    if (std::regex_search(raw.toStdString(), ELEVATION)) {
        snapshot.dnsCache = dns_cache::NeedsAdmin {};
        section.tables << Table { .name = "DNS-кэш резолвера (нужны права администратора)",
                                  .columns = { "Имя", "IP (из кэша)" },
                                  .rows = { { "—", "перезапусти программу от администратора, чтобы увидеть кэш" } } };
    } else {
        auto records = parseDisplayDns(raw);
        const auto suspicious = std::ranges::count_if(records, [](const CacheRecord& r) {
            return std::ranges::any_of(r.ips, [](const AString& ip) { return isSuspiciousCacheIp(ip); });
        });
        Table cache {
            .name = "DNS-кэш резолвера: {} записей (подозрительных: {}). Очищается: ipconfig /flushdns"_format(
                records.size(), suspicious),
            .columns = { "Имя", "IP (из кэша)" },
        };
        for (const auto& r : records | std::views::take(40)) {
            cache.rows << AVector<AString> { r.name, join(r.ips, ", ") };
        }
        if (cache.rows.empty()) {
            cache.rows << AVector<AString> { "—", "кэш пуст" };
        }
        section.tables << std::move(cache);
        snapshot.dnsCache = std::move(records);
    }
    section.text = runRaw({ "netsh", "dns", "show", "global" });
    return section;
}

Section collectRoutes(const NetworkState& network) {
    Section section { .title = "Маршруты / MTU", .text = network.routesText };
    const auto tunnelIps = tunnelInterfaceIps(network.adapters);
    Table defaults { .name = "Маршруты по умолчанию (IPv4, отсортированы по метрике)",
                     .columns = { "Шлюз", "Интерфейс", "Метрика", "Тип" } };
    for (const auto& r : defaultRoutes(network.routes)) {
        defaults.rows << AVector<AString> { r.gateway, r.iface, AString::number(r.metric),
                                            routeThroughTunnel(r, tunnelIps) ? "туннель" : "физический" };
    }
    if (defaults.rows.empty()) {
        defaults.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(defaults);

    // /1../8 capture routes: how Amnezia and others make a full tunnel
    auto capture = tunnelTrafficFraction(network.routes, tunnelIps);
    if (!capture.routes.empty()) {
        std::ranges::sort(capture.routes, {}, [](const Route& r) { return maskToPrefix(r.mask).valueOr(99); });
        Table captured { .name = "Маршруты-захваты через туннель (полный туннель, ~{:.0f}% адресов)"_format(
                             capture.fraction * 100),
                         .columns = { "Сеть", "Интерфейс", "Метрика" } };
        for (const auto& r : capture.routes) {
            captured.rows << AVector<AString> { "{}/{}"_format(r.network, maskToPrefix(r.mask).valueOr(0)),
                                                r.iface, AString::number(r.metric) };
        }
        section.tables << std::move(captured);
    }

    Table interfaces { .name = "Интерфейсы IPv4 (метрика / MTU, через Get-NetIPInterface)",
                       .columns = { "Адаптер", "Метрика", "DHCP", "MTU" } };
    for (const auto& i : items(psJson("Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias,"
                                      "InterfaceMetric,Dhcp,NlMtu | ConvertTo-Json -Compress"))) {
        interfaces.rows << AVector<AString> { field(i, "InterfaceAlias"), field(i, "InterfaceMetric"),
                                              field(i, "Dhcp"), field(i, "NlMtu") };
    }
    section.tables << std::move(interfaces);
    return section;
}

Section collectProxy(SystemSnapshot& snapshot) {
    constexpr AStringView KEY = R"(Software\Microsoft\Windows\CurrentVersion\Internet Settings)";
    Section section { .title = "Прокси" };
    Table wininet { .name = "Системный прокси (WinINET, реестр HKCU)", .columns = { "Параметр", "Значение" } };
    for (AString name : { "ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL", "AutoDetect",
                          "MigrateProxy" }) {
        wininet.rows << AVector<AString> { name, registryValue(HKEY_CURRENT_USER, KEY, name).valueOr("") };
    }
    snapshot.proxy = {
        .enabled = registryValue(HKEY_CURRENT_USER, KEY, "ProxyEnable") == AString("1"),
        .server = registryValue(HKEY_CURRENT_USER, KEY, "ProxyServer").valueOr("?"),
        .pacUrl = registryValue(HKEY_CURRENT_USER, KEY, "AutoConfigURL").valueOr(""),
    };
    section.tables << std::move(wininet);
    section.text = runRaw({ "netsh", "winhttp", "show", "proxy" });

    Table env { .name = "Прокси из переменных окружения", .columns = { "Переменная", "Значение" } };
    for (AString name : { "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ftp_proxy", "HTTP_PROXY",
                          "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY" }) {
        if (auto value = std::getenv(name.toStdString().c_str())) {
            env.rows << AVector<AString> { name, value };
        }
    }
    if (env.rows.empty()) {
        env.rows << AVector<AString> { "—", "не заданы" };
    }
    section.tables << std::move(env);
    return section;
}

Section collectHosts(SystemSnapshot& snapshot) {
    Table table { .name = "Активные записи в hosts", .columns = { "Строка" } };
    try {
        const auto text = AString::fromUtf8(AByteBuffer::fromStream(AFileInputStream(APath(HOSTS_PATH))));
        for (const auto& line : lines(text)) {
            auto s = AString(line.trim(" \t\r"));
            if (!s.empty() && !s.startsWith("#")) {
                snapshot.hostsEntries << s;
                table.rows << AVector<AString> { s };
            }
        }
    } catch (const AException& e) {
        return {
            .title = "hosts",
            .tables = { table },
            .text = "[не удалось прочитать hosts: {}]"_format(e.getMessage()),
        };
    }
    if (table.rows.empty()) {
        table.rows << AVector<AString> { "—" };
    }
    return { .title = "hosts", .tables = { std::move(table) }, .text = "Файл: {}"_format(HOSTS_PATH) };
}

/// PID -> process name from `tasklist /fo csv /nh`.
AVector<std::pair<AString, AString>> tasklist() {
    AVector<std::pair<AString, AString>> result;
    for (const auto& line : lines(runRaw({ "tasklist", "/fo", "csv", "/nh" }))) {
        auto parts = line.split("\",\"");
        if (parts.size() < 2) {
            continue;
        }
        result << std::pair { AString(parts[1].trim('"')), AString(parts[0].trim('"')) };
    }
    return result;
}

Section collectProcesses() {
    Section section { .title = "Процессы / Службы" };
    AMap<AString, AVector<AString>> seen;   // pid -> row
    for (const auto& [pid, name] : tasklist()) {
        if (containsAny(name, VPN_PROCESS_PATTERNS)) {
            seen[pid] = { pid, name, "" };
        }
    }
    for (const auto& p : items(psJson("Get-Process | Select-Object Id,ProcessName,Path | ConvertTo-Json -Compress"))) {
        const auto pid = field(p, "Id");
        const auto name = field(p, "ProcessName");
        const auto path = field(p, "Path");
        if (!containsAny(name, VPN_PROCESS_PATTERNS) && !containsAny(path, VPN_PROCESS_PATTERNS)) {
            continue;
        }
        if (auto it = seen.find(pid); it != seen.end()) {
            it->second[2] = path;
        } else {
            seen[pid] = { pid, name, path };
        }
    }
    Table processes { .name = "Запущенные VPN/прокси-процессы", .columns = { "PID", "Процесс", "Путь" } };
    for (auto& [_, row] : seen) {
        processes.rows << row;
    }
    if (processes.rows.empty()) {
        processes.rows << AVector<AString> { "—", "—", "—" };
    }
    section.tables << std::move(processes);

    AVector<AStringView> servicePatterns(VPN_PROCESS_PATTERNS.begin(), VPN_PROCESS_PATTERNS.end());
    servicePatterns.insert(servicePatterns.end(), VPN_SERVICE_EXTRA_PATTERNS.begin(), VPN_SERVICE_EXTRA_PATTERNS.end());
    Table services { .name = "Службы VPN-инструментов",
                     .columns = { "Имя", "Отображаемое имя", "Состояние", "Тип запуска" } };
    for (const auto& s : items(psJson("Get-Service | Select-Object Name,DisplayName,Status,StartType "
                                      "| ConvertTo-Json -Compress"))) {
        const auto name = field(s, "Name");
        const auto display = field(s, "DisplayName");
        if (!containsAny(name, servicePatterns) && !containsAny(display, servicePatterns)) {
            continue;
        }
        services.rows << AVector<AString> { name, display, translate(field(s, "Status"), SERVICE_STATUS_NAMES),
                                            translate(field(s, "StartType"), SERVICE_START_NAMES) };
    }
    if (services.rows.empty()) {
        services.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(services);
    return section;
}

Section collectFirewall() {
    Section section { .title = "Брандмауэр" };
    Table profiles { .name = "Профили брандмауэра",
                     .columns = { "Профиль", "Включён", "Входящие по умолч.", "Исходящие по умолч." } };
    for (const auto& p : items(psJson("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
                                      "DefaultOutboundAction | ConvertTo-Json -Compress"))) {
        profiles.rows << AVector<AString> {
            translate(field(p, "Name"), FIREWALL_PROFILE),
            translate(field(p, "Enabled"), FIREWALL_ENABLED),
            translate(field(p, "DefaultInboundAction"), FIREWALL_ACTION),
            translate(field(p, "DefaultOutboundAction"), FIREWALL_ACTION),
        };
    }
    section.tables << std::move(profiles);

    Table rules { .name = "Включённые правила брандмауэра, связанные с VPN",
                  .columns = { "Имя правила", "Направление", "Действие", "Профиль" } };
    const auto enabledRules = psJson("Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | "
                                     "Select-Object DisplayName,Direction,Action,Profile | ConvertTo-Json -Compress");
    for (const auto& r : items(enabledRules)) {
        const auto display = field(r, "DisplayName");
        if (!containsAny(display, VPN_PROCESS_PATTERNS)) {
            continue;
        }
        rules.rows << AVector<AString> { display, translate(field(r, "Direction"), FIREWALL_DIRECTION),
                                         translate(field(r, "Action"), FIREWALL_ACTION),
                                         translate(field(r, "Profile"), FIREWALL_PROFILE) };
    }
    if (rules.rows.empty()) {
        rules.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(rules);
    return section;
}

Section collectListeners() {
    AMap<AString, AString> pidName;
    for (const auto& [pid, name] : tasklist()) {
        pidName[pid] = name;
    }
    for (const auto& p : items(psJson("Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"))) {
        pidName.try_emplace(field(p, "Id"), field(p, "ProcessName"));
    }
    Table table { .name = "Слушающие TCP-порты (локальные прокси/сервисы)",
                  .columns = { "Локальный адрес:порт", "PID", "Процесс" } };
    for (const auto& line : lines(runRaw({ "netstat", "-ano", "-p", "tcp" }))) {
        if (!line.contains("LISTENING")) {
            continue;
        }
        auto parts = AString(line.trimDoubleSpace().trim()).split(' ');
        if (parts.size() < 5) {
            continue;
        }
        const auto& local = parts[1];
        const auto& pid = parts.last();
        if (!local.startsWith("127.0.0.1") && !local.startsWith("[::1]") && !local.startsWith("0.0.0.0")) {
            continue;
        }
        auto it = pidName.find(pid);
        table.rows << AVector<AString> { local, pid, it != pidName.end() ? it->second : "?" };
    }
    return { .title = "Порты (netstat)", .tables = { std::move(table) } };
}

Section collectWinsock(SystemSnapshot& snapshot) {
    const auto catalog = runRaw({ "netsh", "winsock", "show", "catalog" });
    snapshot.winsock = parseWinsockCatalog(catalog);
    const auto base = baseLsp(snapshot.winsock);
    const auto third = thirdPartyLsp(snapshot.winsock);
    const auto ns = std::ranges::count_if(snapshot.winsock, [](const WinsockProvider& p) {
        const auto type = p.type.lowercase();
        return type.contains("пространств") || type.contains("namespace");
    });
    Section section { .title = "Winsock / TCP" };
    section.tables << Table {
        .name = "Каталог Winsock — сводка (netsh winsock reset возвращает к стандартному)",
        .columns = { "Метрика", "Значение" },
        .rows = {
            { "Базовых провайдеров (LSP)", AString::number(base.size()) },
            { "Провайдеров пространств имён", AString::number(ns) },
            { "Сторонних (не Microsoft)", AString::number(third.size()) },
        },
    };
    if (!third.empty()) {
        Table t { .name = "Сторонние LSP-провайдеры (сбрасываются командой netsh winsock reset)",
                  .columns = { "Тип", "Описание", "Путь" } };
        for (const auto& p : third) {
            t.rows << AVector<AString> { p.type, p.desc, p.path };
        }
        section.tables << std::move(t);
    }
    section.text = "{}\n\n{}\n\n{}"_format(catalog, runRaw({ "netsh", "int", "tcp", "show", "global" }),
                                           runRaw({ "netsh", "interface", "tcp", "show", "heuristics" }));
    return section;
}

}   // namespace

NetworkState readNetworkState() {
    NetworkState state;
    state.adaptersText = runRaw({ "ipconfig", "/all" });
    state.routesText = runRaw({ "route", "print", "-4" });
    state.adapters = parseIpconfigAdapters(state.adaptersText);
    state.routes = parseRoutePrint(state.routesText);
    return state;
}

SystemSnapshot collectSystem() {
    SystemSnapshot snapshot;
    snapshot.network = readNetworkState();
    snapshot.sections << collectAdapters(snapshot.network);
    snapshot.sections << collectDns(snapshot);
    snapshot.sections << collectRoutes(snapshot.network);
    snapshot.sections << collectProxy(snapshot);
    snapshot.sections << collectHosts(snapshot);
    snapshot.sections << collectProcesses();
    snapshot.sections << collectFirewall();
    snapshot.sections << collectListeners();
    snapshot.sections << collectWinsock(snapshot);
    return snapshot;
}

}   // namespace net

