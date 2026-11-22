#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ranges>
#include <regex>

#include <AUI/Common/AMap.h>

#include "Shell.h"
#include "System.h"

namespace net {

namespace {

namespace fs = std::filesystem;

AOptional<AString> readFile(const fs::path& path) {
    std::ifstream in(path);
    if (!in) {
        return std::nullopt;
    }
    return AString(std::string(std::istreambuf_iterator<char>(in), {}));
}

AString trimmed(AStringView s) { return AString(AString(s).trim(" \t\r\n")); }

AOptional<AJson> json(const AVector<AString>& command) {
    auto text = runRaw(command);
    if (text.startsWith("[")) {
        try {
            return AJson::fromString(text);
        } catch (...) {
        }
    }
    return std::nullopt;
}

AString field(const AJson& object, const AString& key) {
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
    if (item->second.isNumber()) {
        return AString::number(int64_t(item->second.asNumber()));
    }
    return {};
}

AVector<AJson> array(const AOptional<AJson>& json) {
    if (!json || !json->isArray()) {
        return {};
    }
    return AVector<AJson>(json->asArray().begin(), json->asArray().end());
}

AString prefixToMask(int prefix) {
    const uint32_t mask = prefix == 0 ? 0 : ~uint32_t(0) << (32 - prefix);
    return "{}.{}.{}.{}"_format(mask >> 24, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
}

/// "Link 2 (enp39s0): 192.168.100.1" lines of `resolvectl dns`.
AMap<AString, AVector<AString>> linkDns() {
    static const std::regex LINK(R"(^Link \d+ \(([^)]+)\):\s*(.*)$)");
    AMap<AString, AVector<AString>> result;
    for (const auto& line : lines(runRaw({ "resolvectl", "dns" }, 5s))) {
        std::smatch m;
        const auto& s = line.toStdString();
        if (!std::regex_match(s, m, LINK)) {
            continue;
        }
        for (const auto& server : AString(m[2].str()).split(' ')) {
            if (auto d = trimmed(server); !d.empty()) {
                result[AString(m[1].str())] << d;
            }
        }
    }
    return result;
}

AVector<AString> resolvConfServers() {
    AVector<AString> result;
    for (const auto& line : lines(readFile("/etc/resolv.conf").valueOr(""))) {
        auto parts = AString(AString(line).trimDoubleSpace().trim()).split(' ');
        if (parts.size() >= 2 && parts[0] == "nameserver") {
            result << parts[1];
        }
    }
    return result;
}

Section collectAdapters(const NetworkState& network) {
    Table table { .name = "Сетевые адаптеры (ip addr)",
                  .columns = { "Имя", "Описание", "IPv4", "Шлюз", "DNS", "Состояние", "DHCP" } };
    for (const auto& a : network.adapters) {
        table.rows << AVector<AString> { a.name, a.desc, a.ipv4, a.gateway, join(a.dns, ", "), a.status, a.dhcp };
    }
    return { .title = "Адаптеры",
             .tables = { std::move(table) },
             .text = network.adaptersText.empty() ? "[ip addr: пусто]" : network.adaptersText };
}

dns_cache::Records parseResolvedCache(AStringView text) {
    static const std::regex RECORD(R"(^(\S+?)\.? IN (A|AAAA) (\S+)$)");
    AMap<AString, AVector<AString>> byName;
    AVector<AString> order;
    for (const auto& line : lines(text)) {
        std::smatch m;
        const auto s = trimmed(line).toStdString();
        if (!std::regex_match(s, m, RECORD)) {
            continue;
        }
        AString name = m[1].str();
        if (!byName.contains(name)) {
            order << name;
        }
        byName[name] << AString(m[3].str());
    }
    dns_cache::Records records;
    for (const auto& name : order) {
        records << CacheRecord { .name = name, .ips = byName[name] };
    }
    return records;
}

Section collectDns(SystemSnapshot& snapshot) {
    Section section { .title = "DNS" };
    Table resolv { .name = "/etc/resolv.conf", .columns = { "Параметр", "Значение" } };
    for (const auto& line : lines(readFile("/etc/resolv.conf").valueOr(""))) {
        auto s = trimmed(line);
        if (s.empty() || s.startsWith("#")) {
            continue;
        }
        auto space = s.find(' ');
        resolv.rows << AVector<AString> { s.substr(0, space), space == AString::NPOS ? "" : trimmed(s.substr(space)) };
    }
    if (resolv.rows.empty()) {
        resolv.rows << AVector<AString> { "—", "пусто" };
    }
    section.tables << std::move(resolv);

    Table links { .name = "DNS-серверы по интерфейсам (systemd-resolved)", .columns = { "Интерфейс", "DNS" } };
    for (const auto& [link, servers] : linkDns()) {
        links.rows << AVector<AString> { link, join(servers, ", ") };
    }
    if (links.rows.empty()) {
        links.rows << AVector<AString> { "—", "systemd-resolved не используется" };
    }
    section.tables << std::move(links);

    // the resolver cache: exactly what 'resolvectl flush-caches' clears
    if (!isAdmin()) {
        snapshot.dnsCache = dns_cache::NeedsAdmin {};
        section.tables << Table { .name = "DNS-кэш резолвера (нужны права root)",
                                  .columns = { "Имя", "IP (из кэша)" },
                                  .rows = { { "—", "перезапусти программу от root, чтобы увидеть кэш" } } };
    } else if (auto raw = runRaw({ "resolvectl", "show-cache" }, 10s); raw.startsWith("[")) {
        snapshot.dnsCache = dns_cache::Unavailable {};
    } else {
        auto records = parseResolvedCache(raw);
        const auto suspicious = std::ranges::count_if(records, [](const CacheRecord& r) {
            return std::ranges::any_of(r.ips, [](const AString& ip) { return isSuspiciousCacheIp(ip); });
        });
        Table cache { .name = "DNS-кэш резолвера: {} записей (подозрительных: {}). Очищается: resolvectl "
                              "flush-caches"_format(records.size(), suspicious),
                      .columns = { "Имя", "IP (из кэша)" } };
        for (const auto& r : records | std::views::take(40)) {
            cache.rows << AVector<AString> { r.name, join(r.ips, ", ") };
        }
        if (cache.rows.empty()) {
            cache.rows << AVector<AString> { "—", "кэш пуст" };
        }
        section.tables << std::move(cache);
        snapshot.dnsCache = std::move(records);
    }
    section.text = runRaw({ "resolvectl", "status" }, 10s);
    return section;
}

Section collectRoutes(const NetworkState& network) {
    Section section { .title = "Маршруты / MTU", .text = network.routesText };
    const auto tunnelIps = tunnelInterfaceIps(network.adapters);
    Table defaults { .name = "Маршруты по умолчанию (IPv4, все таблицы, отсортированы по метрике)",
                     .columns = { "Шлюз", "Интерфейс", "Метрика", "Тип" } };
    for (const auto& r : defaultRoutes(network.routes)) {
        defaults.rows << AVector<AString> { r.gateway, r.iface, AString::number(r.metric),
                                            routeThroughTunnel(r, tunnelIps) ? "туннель" : "физический" };
    }
    if (defaults.rows.empty()) {
        defaults.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(defaults);

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

    Table interfaces { .name = "Интерфейсы (MTU, ip link)", .columns = { "Адаптер", "Состояние", "Тип", "MTU" } };
    for (const auto& link : array(json({ "ip", "-j", "link" }))) {
        interfaces.rows << AVector<AString> { field(link, "ifname"), field(link, "operstate"), field(link, "link_type"),
                                              field(link, "mtu") };
    }
    section.tables << std::move(interfaces);
    return section;
}

AString gsetting(AStringView schema, AStringView key) {
    auto value = runRaw({ "gsettings", "get", AString(schema), AString(key) }, 5s);
    if (value.startsWith("[")) {
        return {};
    }
    return AString(AString(value.trim()).trim('\''));
}

Section collectProxy(SystemSnapshot& snapshot) {
    Section section { .title = "Прокси" };
    const auto mode = gsetting("org.gnome.system.proxy", "mode");
    if (!mode.empty()) {
        Table gnome { .name = "Системный прокси (GNOME, gsettings)", .columns = { "Параметр", "Значение" } };
        gnome.rows << AVector<AString> { "mode", mode };
        AString server;
        for (AString kind : { "https", "http", "socks" }) {
            const auto schema = "org.gnome.system.proxy.{}"_format(kind);
            const auto host = gsetting(schema, "host");
            const auto port = gsetting(schema, "port");
            const auto value = host.empty() ? AString {} : "{}:{}"_format(host, port);
            gnome.rows << AVector<AString> { kind, value };
            if (server.empty()) {
                server = value;
            }
        }
        const auto pac = gsetting("org.gnome.system.proxy", "autoconfig-url");
        gnome.rows << AVector<AString> { "autoconfig-url", pac };
        snapshot.proxy = {
            .enabled = mode == "manual",
            .server = server.empty() ? AString("?") : server,
            .pacUrl = mode == "auto" ? pac : AString {},
        };
        section.tables << std::move(gnome);
    }

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
    constexpr AStringView HOSTS_PATH = "/etc/hosts";
    Table table { .name = "Активные записи в hosts", .columns = { "Строка" } };
    auto text = readFile(fs::path(std::string(HOSTS_PATH)));
    if (!text) {
        return { .title = "hosts", .tables = { table }, .text = "[не удалось прочитать hosts]" };
    }
    for (const auto& line : lines(*text)) {
        auto s = trimmed(line);
        if (!s.empty() && !s.startsWith("#")) {
            snapshot.hostsEntries << s;
            table.rows << AVector<AString> { s };
        }
    }
    if (table.rows.empty()) {
        table.rows << AVector<AString> { "—" };
    }
    return { .title = "hosts", .tables = { std::move(table) }, .text = "Файл: {}"_format(HOSTS_PATH) };
}

struct Process {
    AString pid;
    AString name;
    AString path;
};

AVector<Process> processes() {
    AVector<Process> result;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/proc", ec)) {
        const auto pid = entry.path().filename().string();
        if (!std::ranges::all_of(pid, [](char c) { return c >= '0' && c <= '9'; })) {
            continue;
        }
        auto name = readFile(entry.path() / "comm");
        if (!name) {
            continue;
        }
        std::error_code linkError;
        auto exe = fs::read_symlink(entry.path() / "exe", linkError);
        result << Process {
            .pid = pid,
            .name = trimmed(*name),
            .path = linkError ? AString {} : AString(exe.string()),
        };
    }
    std::ranges::sort(result, {}, [](const Process& p) { return std::stoi(p.pid.toStdString()); });
    return result;
}

AString translateUnitState(const AString& active, const AString& sub) {
    static const AMap<AString, AString> SUB = {
        { "running", "Работает" },   { "exited", "Завершилась" }, { "dead", "Остановлена" },
        { "failed", "Сбой" },        { "start", "Запускается" },  { "stop", "Останавливается" },
        { "auto-restart", "Перезапуск" },
    };
    if (auto it = SUB.find(sub); it != SUB.end()) {
        return it->second;
    }
    return "{} ({})"_format(active, sub);
}

AString translateEnabled(const AString& state) {
    static const AMap<AString, AString> MAP = {
        { "enabled", "Авто" }, { "disabled", "Отключена" }, { "static", "Статическая" },
        { "masked", "Заблокирована" }, { "indirect", "Косвенная" }, { "generated", "Сгенерирована" },
    };
    auto it = MAP.find(state);
    return it != MAP.end() ? it->second : state;
}

Section collectProcesses() {
    Section section { .title = "Процессы / Службы" };
    Table procs { .name = "Запущенные VPN/прокси-процессы", .columns = { "PID", "Процесс", "Путь" } };
    for (const auto& p : processes()) {
        if (containsAny(p.name, VPN_PROCESS_PATTERNS) || containsAny(p.path, VPN_PROCESS_PATTERNS)) {
            procs.rows << AVector<AString> { p.pid, p.name, p.path };
        }
    }
    if (procs.rows.empty()) {
        procs.rows << AVector<AString> { "—", "—", "—" };
    }
    section.tables << std::move(procs);

    AVector<AStringView> patterns(VPN_PROCESS_PATTERNS.begin(), VPN_PROCESS_PATTERNS.end());
    patterns.insert(patterns.end(), VPN_SERVICE_EXTRA_PATTERNS.begin(), VPN_SERVICE_EXTRA_PATTERNS.end());
    Table services { .name = "Службы VPN-инструментов (systemd)",
                     .columns = { "Имя", "Отображаемое имя", "Состояние", "Тип запуска" } };
    for (const auto& line : lines(runRaw(
             { "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager" }))) {
        auto parts = AString(AString(line).trimDoubleSpace().trim()).split(' ');
        if (parts.size() < 4) {
            continue;
        }
        AString description;
        for (size_t i = 4; i < parts.size(); ++i) {
            description += (description.empty() ? "" : " ") + parts[i];
        }
        if (!containsAny(parts[0], patterns) && !containsAny(description, patterns)) {
            continue;
        }
        const auto enabled = trimmed(runRaw({ "systemctl", "is-enabled", parts[0] }, 5s));
        services.rows << AVector<AString> { parts[0], description, translateUnitState(parts[2], parts[3]),
                                            translateEnabled(enabled) };
    }
    if (services.rows.empty()) {
        services.rows << AVector<AString> { "—", "—", "—", "—" };
    }
    section.tables << std::move(services);
    return section;
}

Section collectFirewall() {
    Section section { .title = "Брандмауэр" };
    Table state { .name = "Состояние брандмауэра", .columns = { "Средство", "Состояние" } };
    state.rows << AVector<AString> { "firewalld", runRaw({ "firewall-cmd", "--state" }, 5s) };
    if (auto ufw = runRaw({ "ufw", "status" }, 5s); !ufw.startsWith("[ошибка")) {
        state.rows << AVector<AString> { "ufw", lines(ufw).first() };
    }
    const auto ruleset = isAdmin() ? runRaw({ "nft", "list", "ruleset" }) : AString {};
    if (ruleset.empty()) {
        state.rows << AVector<AString> { "nftables", isAdmin() ? "правил нет" : "нужны права root" };
    } else {
        const auto tables =
            std::ranges::count_if(lines(ruleset), [](const AString& l) { return l.startsWith("table "); });
        state.rows << AVector<AString> { "nftables", "{} таблиц"_format(tables) };
    }
    section.tables << std::move(state);

    Table rules { .name = "Правила nftables, связанные с VPN", .columns = { "Правило" } };
    for (const auto& line : lines(ruleset)) {
        if (containsAny(line, VPN_PROCESS_PATTERNS) || containsAny(line, VPN_ADAPTER_PATTERNS)) {
            rules.rows << AVector<AString> { trimmed(line) };
        }
    }
    if (rules.rows.empty()) {
        rules.rows << AVector<AString> { isAdmin() ? "—" : "— (нужны права root)" };
    }
    section.tables << std::move(rules);
    return section;
}

Section collectListeners() {
    static const std::regex PROCESS(R"re(\(\("([^"]+)",pid=(\d+))re");
    Table table { .name = "Слушающие TCP-порты (локальные прокси/сервисы)",
                  .columns = { "Локальный адрес:порт", "PID", "Процесс" } };
    for (const auto& line : lines(runRaw({ "ss", "-ltnpH" }))) {
        auto parts = AString(AString(line).trimDoubleSpace().trim()).split(' ');
        if (parts.size() < 5) {
            continue;
        }
        const auto& local = parts[3];
        static constexpr auto LOCAL =
            std::to_array<AStringView>({ "127.0.0.1", "[::1]", "0.0.0.0", "[::]", "*" });
        if (!std::ranges::any_of(LOCAL, [&](AStringView p) { return local.startsWith(p); })) {
            continue;
        }
        std::smatch m;
        const auto& s = line.toStdString();
        if (std::regex_search(s, m, PROCESS)) {
            table.rows << AVector<AString> { local, m[2].str(), m[1].str() };
        } else {
            table.rows << AVector<AString> { local, "?", "?" };
        }
    }
    return { .title = "Порты (ss)", .tables = { std::move(table) } };
}

Section collectTcp() {
    static constexpr auto PARAMS = std::to_array<AStringView>({
        "net/ipv4/tcp_congestion_control",
        "net/ipv4/tcp_available_congestion_control",
        "net/core/default_qdisc",
        "net/ipv4/tcp_mtu_probing",
        "net/ipv4/tcp_ecn",
        "net/ipv4/tcp_fastopen",
        "net/ipv4/ip_forward",
        "net/ipv4/conf/all/rp_filter",
        "net/ipv6/conf/all/disable_ipv6",
    });
    Table table { .name = "Параметры TCP/IP ядра (/proc/sys)", .columns = { "Параметр", "Значение" } };
    for (auto param : PARAMS) {
        auto key = AString(param);
        auto value = readFile(fs::path("/proc/sys") / std::string(param));
        table.rows << AVector<AString> { key.replacedAll("/", "."), value ? trimmed(*value) : AString("н/д") };
    }
    return { .title = "TCP (sysctl)", .tables = { std::move(table) } };
}

}   // namespace

NetworkState readNetworkState() {
    NetworkState state;
    state.adaptersText = runRaw({ "ip", "addr" });
    state.routesText = "{}\n\n{}"_format(runRaw({ "ip", "-4", "route", "show", "table", "all" }),
                                         runRaw({ "ip", "-4", "rule" }));

    const auto routes = array(json({ "ip", "-j", "-4", "route", "show", "table", "all" }));
    const auto dnsByLink = linkDns();

    AMap<AString, AString> ifaceIp;
    for (const auto& link : array(json({ "ip", "-j", "-d", "addr" }))) {
        Adapter adapter;
        adapter.name = field(link, "ifname");
        if (adapter.name.empty() || adapter.name == "lo") {
            continue;
        }
        adapter.rawName = adapter.name;
        const auto kind = [&] {
            if (auto info = link.asObject().contains("linkinfo"); info && info->second.isObject()) {
                return field(info->second, "info_kind");
            }
            return AString {};
        }();
        adapter.desc = kind.empty() ? field(link, "link_type") : kind;
        adapter.status = field(link, "operstate");
        bool dynamic = false;
        if (auto addrs = link.asObject().contains("addr_info"); addrs && addrs->second.isArray()) {
            for (const auto& a : addrs->second.asArray()) {
                if (field(a, "family") == "inet" && adapter.ipv4.empty()) {
                    adapter.ipv4 = field(a, "local");
                }
                if (auto d = a.asObject().contains("dynamic"); d && d->second.isBool() && d->second.asBool()) {
                    dynamic = true;
                }
            }
        }
        adapter.dhcp = dynamic ? "Да" : "Нет";
        for (const auto& r : routes) {
            if (field(r, "dst") == "default" && field(r, "dev") == adapter.name && field(r, "table").empty()) {
                adapter.gateway = field(r, "gateway");
            }
        }
        if (auto it = dnsByLink.find(adapter.name); it != dnsByLink.end()) {
            adapter.dns = it->second;
        }
        ifaceIp[adapter.name] = adapter.ipv4;
        state.adapters << std::move(adapter);
    }

    // no systemd-resolved: the resolv.conf servers belong to the adapter with the main default route
    if (dnsByLink.empty()) {
        for (auto& a : state.adapters) {
            if (!a.gateway.empty()) {
                a.dns = resolvConfServers();
                break;
            }
        }
    }

    for (const auto& r : routes) {
        const auto type = field(r, "type");
        if (!type.empty() && type != "unicast") {
            continue;
        }
        auto dst = field(r, "dst");
        const auto dev = field(r, "dev");
        Route route;
        if (dst == "default") {
            route.network = "0.0.0.0";
            route.mask = "0.0.0.0";
        } else {
            auto slash = dst.find('/');
            route.network = dst.substr(0, slash);
            const auto prefix = slash == AString::NPOS ? 32 : AStringView(dst.substr(slash + 1)).toInt().valueOr(32);
            route.mask = prefixToMask(prefix);
        }
        auto gw = field(r, "gateway");
        route.gateway = gw.empty() ? AString("On-link") : gw;
        auto ip = ifaceIp.find(dev);
        route.iface = ip != ifaceIp.end() && !ip->second.empty() ? ip->second : dev;
        route.metric = field(r, "metric").toInt().valueOr(0);
        state.routes << std::move(route);
    }
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
    snapshot.sections << collectTcp();
    return snapshot;
}

}   // namespace net

