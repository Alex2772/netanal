#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetUtil — диагностика сетевых конфигураций Windows 11.

Назначение
----------
Проверяет ВСЕ сетевые конфигурации Windows и в режиме онлайн определяет,
что именно «отвалилось» после работы VPN-обходчиков (Amnezia WG, VLESS,
sing-box, xray, Hiddify/Happ, Hysteria, tun2socks и т.п.):

  * адаптеры (включая «мусорные» TUN/TAP/Wintun/Amnezia/sing-box);
  * DNS (серверы на адаптерах, глобальные настройки, DoH, NRPT-политики,
    кэш, прямые запросы к публичным резолверам);
  * маршруты (шлюзы по умолчанию, метрики, MTU);
  * прокси (системный WinINET, WinHTTP, переменные окружения);
  * hosts-файл;
  * процессы и службы VPN-инструментов;
  * правила брандмауэра;
  * каталог Winsock (LSP), настройки TCP;
  * живые соединения / слушающие порты (остаточные прокси-порты).

Запуск
------
    python netutil.py            # GUI
    python netutil.py --cli      # только текст в консоль
    python netutil.py --export report.json   # сохранить снимок в JSON (без GUI)

Требования: Python 3.8+, Windows. Используется только стандартная библиотека.
Запуск от администратора даёт больше данных (службы, часть DNS-кэша, firewall).
"""

import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
import queue as _queue
from concurrent.futures import ThreadPoolExecutor, as_completed

try:  # GUI (для --cli на системах без Tk продолжаем работать)
    import tkinter as tk
    from tkinter import ttk
except Exception:  # noqa: BLE001
    tk = None
    ttk = None

# ----------------------------------------------------------------------------
# Настройки проверок
# ----------------------------------------------------------------------------

DEFAULT_RU_SITES = [
    ("Яндекс", "https://ya.ru"),
    ("VK", "https://vk.com"),
    ("Mail.ru", "https://mail.ru"),
    ("Госуслуги", "https://www.gosuslugi.ru"),
    ("Сбербанк", "https://www.sberbank.ru"),
    ("РБК", "https://www.rbc.ru"),
    ("Ozon", "https://www.ozon.ru"),
    ("Wildberries", "https://www.wildberries.ru"),
    ("Avito", "https://www.avito.ru"),
    ("Rambler", "https://www.rambler.ru"),
    ("Лента", "https://lenta.ru"),
    ("2ГИС", "https://2gis.ru"),
    ("Тинькофф", "https://www.tinkoff.ru"),
    ("Кинопоиск", "https://www.kinopoisk.ru"),
    ("РИА", "https://ria.ru"),
    ("Газета.ру", "https://www.gazeta.ru"),
    ("Коммерсантъ", "https://www.kommersant.ru"),
    ("Ведомости", "https://www.vedomosti.ru"),
    ("Яндекс.Маркет", "https://market.yandex.ru"),
    ("Дзен", "https://dzen.ru"),
    ("Мегафон", "https://www.megafon.ru"),
    ("МТС", "https://www.mts.ru"),
    ("Пикабу", "https://pikabu.ru"),
    ("Хабр", "https://habr.com"),
    ("Почта России", "https://www.pochta.ru"),
]

DEFAULT_FOREIGN_SITES = [
    ("Microsoft", "https://www.microsoft.com"),
    ("Apple", "https://www.apple.com"),
    ("Cloudflare", "https://www.cloudflare.com"),
    ("Википедия", "https://ru.wikipedia.org"),
    ("GitHub", "https://github.com"),
    ("OpenAI", "https://openai.com"),
    ("Amazon", "https://www.amazon.com"),
    ("Netflix", "https://www.netflix.com"),
    ("Reddit", "https://www.reddit.com"),
    ("StackOverflow", "https://stackoverflow.com"),
    ("DuckDuckGo", "https://duckduckgo.com"),
    ("Dropbox", "https://www.dropbox.com"),
    ("Google", "https://www.google.com"),
    ("Bing", "https://www.bing.com"),
    ("Yahoo", "https://www.yahoo.com"),
    ("Spotify", "https://www.spotify.com"),
    ("Twitch", "https://www.twitch.tv"),
    ("Adobe", "https://www.adobe.com"),
    ("WordPress", "https://wordpress.com"),
    ("Archive.org", "https://archive.org"),
    ("BBC", "https://www.bbc.com"),
    ("CNN", "https://edition.cnn.com"),
    ("Reuters", "https://www.reuters.com"),
    ("Python", "https://www.python.org"),
    ("Mozilla", "https://www.mozilla.org"),
]

DEFAULT_BLOCKED_SITES = [
    ("Instagram", "https://www.instagram.com"),
    ("Facebook", "https://www.facebook.com"),
    ("X / Twitter", "https://x.com"),
    ("YouTube", "https://www.youtube.com"),
    ("Discord", "https://discord.com"),
    ("LinkedIn", "https://www.linkedin.com"),
    ("TikTok", "https://www.tiktok.com"),
    ("Medium", "https://medium.com"),
    ("OnlyFans", "https://onlyfans.com"),
    ("BBC", "https://www.bbc.com"),
    ("Deutsche Welle", "https://www.dw.com"),
    ("RFE/RL", "https://www.rferl.org"),
    ("Tor Project", "https://www.torproject.org"),
    ("Proton", "https://proton.me"),
    ("OpenAI", "https://openai.com"),
    ("Anthropic", "https://www.anthropic.com"),
    ("Threads", "https://www.threads.net"),
    ("Messenger", "https://www.messenger.com"),
    ("Signal", "https://signal.org"),
    ("Clubhouse", "https://www.clubhouse.com"),
    ("Meduza", "https://meduza.io"),
    ("Novaya Gazeta", "https://novayagazeta.eu"),
    ("The Insider", "https://theinsider.press"),
    ("iStories", "https://istories.media"),
    ("Bellingcat", "https://www.bellingcat.com"),
]

# Пользовательские списки: sites.json рядом с утилитой (иначе — дефолтные).
SITES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "sites.json")


def _name_from_url(url):
    try:
        host = urllib.parse.urlparse(url).netloc
        return host or url
    except Exception:  # noqa: BLE001
        return url


def _load_sites_file():
    try:
        with open(SITES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001
        return {"RU": list(DEFAULT_RU_SITES),
                "Зарубежные": list(DEFAULT_FOREIGN_SITES),
                "Заблокированные": list(DEFAULT_BLOCKED_SITES)}
    out = {}
    for zone, default in (("RU", DEFAULT_RU_SITES),
                          ("Зарубежные", DEFAULT_FOREIGN_SITES),
                          ("Заблокированные", DEFAULT_BLOCKED_SITES)):
        items = data.get(zone)
        parsed = []
        if isinstance(items, list):
            for it in items:
                if isinstance(it, str) and it.strip():
                    parsed.append((_name_from_url(it.strip()), it.strip()))
                elif isinstance(it, (list, tuple)) and len(it) >= 2:
                    parsed.append((str(it[0]), str(it[1])))
        out[zone] = parsed or list(default)
    return out


def save_site_lists(data):
    """data: {зона: [(name, url), ...]} -> sites.json."""
    try:
        payload = {z: [[n, u] for n, u in items] for z, items in data.items()}
        with open(SITES_FILE, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return True
    except Exception:  # noqa: BLE001
        return False


def reload_site_lists():
    """Перечитать sites.json и обновить глобальные списки."""
    global RU_SITES, FOREIGN_SITES, BLOCKED_SITES, ZONE_SITES
    data = _load_sites_file()
    RU_SITES = data["RU"]
    FOREIGN_SITES = data["Зарубежные"]
    BLOCKED_SITES = data["Заблокированные"]
    ZONE_SITES = {"RU": RU_SITES, "Зарубежные": FOREIGN_SITES,
                  "Заблокированные": BLOCKED_SITES}


_init_sites = _load_sites_file()
RU_SITES = _init_sites["RU"]
FOREIGN_SITES = _init_sites["Зарубежные"]
BLOCKED_SITES = _init_sites["Заблокированные"]

DNS_SERVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Cloudflare-2", "1.0.0.1"),
    ("Google", "8.8.8.8"),
    ("Google-2", "8.8.4.4"),
    ("Quad9", "9.9.9.9"),
    ("Яндекс DNS", "77.88.8.8"),
]

# Эндпоинты для замера скорости по зонам (крупные статичные файлы, без rate-limit).
SPEED_ENDPOINTS = {
    "RU": ["https://mirror.yandex.ru/ubuntu/dists/jammy/Contents-amd64.gz"],
    "Зарубежные": ["https://cachefly.cachefly.net/100mb.test",
                   "https://proof.ovh.net/files/100Mb.dat"],
    "Заблокированные": ["https://cachefly.cachefly.net/100mb.test",
                        "https://proof.ovh.net/files/100Mb.dat"],
}

# Echo-сервисы для определения IP по зонам (русский — check-host.net,
# зарубежный — ipify/ifconfig.me). При split-роутинге IP будут различаться.
# NB: надёжных RU echo мало (почти все за CDN), поэтому RU-зону определяем
# иначе — по локальному пути соединения (detect_egress).
ECHO_SERVERS = {
    "RU": ["https://ip.mail.ru/", "https://check-host.net/ip"],
    "Зарубежные": ["https://api.ipify.org?format=json", "https://ifconfig.me/ip"],
    "Заблокированные": ["https://api.ipify.org?format=json"],
}

# Куда коннектимся для определения локального пути зоны (напрямую/туннель)
ZONE_PROBE_HOSTS = {
    "RU": "ya.ru",
    "Зарубежные": "cloudflare.com",
    "Заблокированные": "instagram.com",
}

ZONES = ["RU", "Зарубежные", "Заблокированные"]
ZONE_SITES = {"RU": RU_SITES, "Зарубежные": FOREIGN_SITES,
              "Заблокированные": BLOCKED_SITES}

# Маркеры имён для поиска «мусора», оставленного обходчиками.
VPN_PROCESS_PATTERNS = [
    "xray", "sing-box", "singbox", "hysteria", "hiddify", "amnezia", "clash",
    "v2ray", "tun2socks", "happ", "nekoray", "nekobox", "mihomo", "wireguard",
    "openvpn", "shadowsocks", "ss-local", "ssr", "trojan", "warp-svc", "cloudflared",
    "tailscale", "zerotier", "outline", "psiphon", "sstap", "naiveproxy",
]

VPN_SERVICE_PATTERNS = VPN_PROCESS_PATTERNS + [
    "wg-quick", "nordvpn", "protonvpn", "cloudflarewarp",
]

VPN_ADAPTER_PATTERNS = [
    "tap", "tun", "wintun", "amnezia", "sing-box", "singbox", "hiddify", "xray",
    "wireguard", "openvpn", "utun", "hysteria", "warp", "tailscale", "zerotier",
    "outline", "psiphon", "nordlynx", "metavpn", "vpngate", "wiresock",
    "tun2socks", "clash", "mihomo",
]

VM_ADAPTER_PATTERNS = ["vmware", "virtualbox", "hyper-v", "vnet"]

CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ----------------------------------------------------------------------------
# Низкоуровневые помощники
# ----------------------------------------------------------------------------

def _oem_codepage():
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetOEMCP())
    except Exception:  # noqa: BLE001
        return None


def decode_bytes(data: bytes) -> str:
    """Раскодировать вывод консольных утилит (OEM-кодировка на русской Windows)."""
    if not data:
        return ""
    oem = _oem_codepage()
    candidates = ["utf-8"]
    if oem:
        candidates.append("cp%d" % oem)
    candidates += ["cp866", "cp1251", "cp437", "latin-1"]
    for enc in candidates:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def run_raw(cmd, timeout=20):
    """Запустить системную команду, вернуть раскодированный текст."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        out = decode_bytes(r.stdout)
        err = decode_bytes(r.stderr)
        return (out + ("\n" + err if err.strip() else "")).strip()
    except subprocess.TimeoutExpired:
        return "[таймаут]"
    except Exception as e:  # noqa: BLE001
        return f"[ошибка: {e}]"


def ps_json(cmd, timeout=40):
    """Выполнить PowerShell-команду и вернуть распарсенный JSON (или None)."""
    full = ("[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd)
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", full],
            capture_output=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)
        out = r.stdout.decode("utf-8", errors="replace").strip()
        if not out:
            return None
        return json.loads(out)
    except Exception:  # noqa: BLE001
        return None


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


_IPISH = re.compile(r"^[0-9a-fA-F.:%]+$")


def is_tunnel_ip(ip: str) -> bool:
    """IP в диапазонах, характерных для туннелей (CGNAT / test-net / APIPA)."""
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in ("100.64.0.0/10", "198.18.0.0/15", "169.254.0.0/16"):
        if a in ipaddress.ip_network(net):
            return True
    return False


def mask_to_prefix(mask: str):
    """Маска подсети -> длина префикса (255.0.0.0 -> 8, 128.0.0.0 -> 1)."""
    try:
        import ipaddress
        return bin(int(ipaddress.IPv4Address(mask))).count("1")
    except Exception:  # noqa: BLE001
        return None


def tunnel_interface_ips(adapters):
    """IPv4-адреса туннельных адаптеров (по ним опознаём туннель в маршрутах)."""
    ips = set()
    for a in adapters:
        if any(pat in (a["name"] + " " + a["desc"]).lower()
               for pat in VPN_ADAPTER_PATTERNS):
            if a["ipv4"]:
                ips.add(a["ipv4"])
    return ips


def route_through_tunnel(r, tunnel_ips) -> bool:
    """Идёт ли маршрут через туннель (интерфейс = IP туннельного адаптера)."""
    return r["interface"] in tunnel_ips


def tunnel_traffic_fraction(routes, tunnel_ips):
    """Доля IPv4-пространства, уходящая в туннель.
    Учитывает capture-маршруты /1, /2 ... /8 (их использует Amnezia и др.).
    Возвращает (доля, список таких маршрутов)."""
    total = 0.0
    captured = []
    for r in routes:
        if not route_through_tunnel(r, tunnel_ips):
            continue
        if r["network"].startswith(("224.", "239.")):  # multicast не считаем
            continue
        plen = mask_to_prefix(r["mask"])
        if plen is None or plen > 8:
            continue
        total += 2.0 ** (-plen)
        captured.append(r)
    return total, captured


def parse_route_print(text: str) -> list:
    """Разобрать 'route print -4' в список маршрутов."""
    routes = []
    in_active = False
    for line in text.splitlines():
        if re.search(r"Активные маршруты|Active Routes", line):
            in_active = True
            continue
        if re.search(r"Постоянные маршруты|Persistent Routes", line):
            in_active = False
            continue
        if not in_active:
            continue
        m = re.match(
            r"^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+"
            r"(\S+)\s+(\S+)\s+(\d+)\s*$", line)
        if m:
            routes.append({
                "network": m.group(1), "mask": m.group(2),
                "gateway": m.group(3), "interface": m.group(4),
                "metric": int(m.group(5)),
            })
    return routes


def parse_ipconfig_adapters(text: str) -> list:
    """Разобрать вывод 'ipconfig /all' в список адаптеров."""
    adapters = []
    cur = None
    last_field = None
    for line in text.splitlines():
        # Заголовок адаптера — строка без отступа, оканчивающаяся на ':'
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            raw_name = line.strip().rstrip(":").strip()
            unknown = False
            name = raw_name
            for pref in ("Неизвестный адаптер", "Unknown adapter"):
                if name.lower().startswith(pref.lower() + " "):
                    unknown = True
                    name = name[len(pref) + 1:].strip()
                    break
            for pref in ("Адаптер Ethernet", "Ethernet adapter",
                         "Адаптер беспроводной локальной сети",
                         "Wireless LAN adapter", "Адаптер туннеля",
                         "Tunnel adapter", "Адаптер", "Adapter"):
                if name.lower().startswith(pref.lower() + " "):
                    name = name[len(pref) + 1:].strip()
                    break
            cur = {"name": name, "raw_name": raw_name, "unknown": unknown,
                   "desc": "", "ipv4": "", "gateway": "", "dns": [],
                   "status": "", "dhcp": ""}
            adapters.append(cur)
            last_field = None
            continue
        if cur is None:
            continue
        s = line.strip()
        m = re.match(r"^(.+?)\s*\.+\s*:\s*(.*)$", s)
        if m:
            key, val = m.group(1).strip(), m.group(2).strip()
            kl = key.lower()
            if "описание" in kl or "description" in kl:
                cur["desc"] = val
                last_field = None
            elif "ipv4" in kl and ("адрес" in kl or "address" in kl):
                cur["ipv4"] = val.split("(")[0].split("%")[0].strip()
                last_field = None
            elif "шлюз" in kl or "gateway" in kl:
                cur["gateway"] = val
                last_field = "gateway"
            elif "состояние среды" in kl or "media state" in kl:
                cur["status"] = val
                last_field = None
            elif "dhcp" in kl and ("включен" in kl or "enabled" in kl):
                cur["dhcp"] = val
                last_field = None
            elif "dns" in kl and "суффикс" not in kl and "suffix" not in kl:
                if val:
                    cur["dns"].append(val)
                last_field = "dns"
            else:
                last_field = None
        else:
            if s and last_field == "dns" and _IPISH.match(s):
                cur["dns"].append(s)
            elif s and last_field == "gateway":
                cur["gateway"] += " " + s
    return adapters


def parse_displaydns(text: str) -> list:
    """Разобрать 'ipconfig /displaydns' в список записей кэша {name, ips}."""
    records = []
    cur = None
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if "Имя записи" in s or "Record Name" in s:
            m = re.search(r":\s*(.+)$", s)
            if cur:
                records.append(cur)
            cur = {"name": m.group(1).strip() if m else s, "ips": []}
            continue
        if cur is not None and ("Запись" in s or "Record" in s) and ":" in s:
            val = s.split(":", 1)[1].strip()
            if _IPISH.match(val):
                cur["ips"].append(val)
    if cur:
        records.append(cur)
    return records


def parse_winsock_catalog(text: str) -> list:
    """Разобрать 'netsh winsock show catalog' в список провайдеров."""
    providers = []
    for block in re.split(r"Элемент поставщика", text):
        desc = re.search(r"Описание\s*[:.]+\s*(.+)", block)
        path = re.search(r"Путь поставщика\s*[:.]+\s*(.+)", block)
        ptype = re.search(r"Тип элемента\s*[:.]+\s*(.+)", block)
        if desc:
            providers.append({
                "type": ptype.group(1).strip() if ptype else "",
                "desc": desc.group(1).strip(),
                "path": path.group(1).strip() if path else "",
            })
    return providers


def is_suspicious_cache_ip(ip: str) -> bool:
    """Подозрительный адрес в DNS-кэше (loopback/частный/0.0.0.0) — признак подмены."""
    if ip == "0.0.0.0" or ip == "::":
        return True
    if ip.startswith(("127.", "10.", "192.168.", "100.64.", "100.65.",
                      "198.18.", "169.254.")):
        return True
    return ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31


# Карты состояний служб Windows (Get-Service отдаёт числовые коды)
SERVICE_STATUS_MAP = {1: "Остановлена", 2: "Запускается", 3: "Останавливается",
                      4: "Работает", 5: "Продолжается", 6: "Приостанавливается",
                      7: "Приостановлена"}
SERVICE_START_MAP = {0: "Загрузка", 1: "Система", 2: "Авто", 3: "Вручную",
                     4: "Отключена"}

# Расшифровка значений брандмауэра Windows
FIREWALL_PROFILE_MAP = {"Domain": "Домен", "Private": "Частная",
                        "Public": "Общедоступная", "Any": "Любой"}
FIREWALL_ACTION_MAP = {"Allow": "Разрешить", "Block": "Блокировать",
                       "NotConfigured": "Не настроено"}
FIREWALL_DIRECTION_MAP = {"Inbound": "Входящее", "Outbound": "Исходящее"}
FIREWALL_ENABLED_MAP = {"True": "Да", "False": "Нет"}


def translate_val(value, mapping):
    """Перевести значение (или список через запятую) по словарю."""
    if value is None:
        return ""
    s = str(value)
    if "," in s:
        return ", ".join(mapping.get(p.strip(), p.strip())
                         for p in s.split(",") if p.strip())
    return mapping.get(s, s)


# ----------------------------------------------------------------------------
# DNS-утилиты (сырые UDP-запросы к публичным резолверам)
# ----------------------------------------------------------------------------

def _skip_name(data: bytes, off: int) -> int:
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += 1 + length


def _parse_a(data: bytes, qd: int) -> list:
    ips = []
    try:
        off = 12
        for _ in range(qd):
            off = _skip_name(data, off) + 4
        an = struct.unpack(">H", data[6:8])[0]
        for _ in range(an):
            off = _skip_name(data, off)
            rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(rdata))
    except Exception:  # noqa: BLE001
        pass
    return ips


def dns_udp_query(server: str, host: str, timeout=3.0) -> dict:
    """Отправить DNS-запрос напрямую на сервер (UDP/53) и измерить задержку."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(lbl)]) + lbl.encode("idna")
        for lbl in host.split(".") if lbl
    ) + b"\x00"
    packet = header + qname + struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t0 = time.perf_counter()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
        rtt = (time.perf_counter() - t0) * 1000.0
        _rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        rcode = flags & 0x000F
        ips = _parse_a(data, qd)
        return {"ok": True, "rtt_ms": round(rtt, 1), "rcode": rcode,
                "answers": an, "ips": ips}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        sock.close()


def resolve_host(host: str, timeout=None) -> dict:
    """DNS-резолв. timeout — жёсткий лимит: getaddrinfo сам таймаута не умеет,
    поэтому при timeout крутим его в отдельном потоке и ждём не дольше."""
    if timeout is None:
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC,
                                       socket.SOCK_STREAM)
            ips = sorted({i[4][0] for i in infos})
            return {"ok": True, "ips": ips}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    q = _queue.Queue()

    def worker():
        try:
            q.put(("ok", socket.getaddrinfo(host, 443, socket.AF_UNSPEC,
                                            socket.SOCK_STREAM)))
        except Exception as e:  # noqa: BLE001
            q.put(("err", str(e)))

    threading.Thread(target=worker, daemon=True).start()
    try:
        kind, val = q.get(timeout=timeout)
    except _queue.Empty:
        return {"ok": False, "error": "DNS таймаут"}
    if kind == "err":
        return {"ok": False, "error": val}
    ips = sorted({i[4][0] for i in val})
    return {"ok": True, "ips": ips}


def tcp_test(host: str, port: int = 443, timeout=4.0, ip: str = None) -> dict:
    """TCP-connect RTT (~1 RTT, честный «пинг»). ip — заранее резолвленный
    адрес, чтобы в замер не попадало время DNS-резолвинга."""
    target = ip or host
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((target, port), timeout=timeout)
        rtt = (time.perf_counter() - t0) * 1000.0
        sock.close()
        return {"ok": True, "rtt_ms": round(rtt, 1)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def http_test(url: str, use_system_proxy: bool = True, timeout=8.0) -> dict:
    try:
        t0 = time.perf_counter()
        if use_system_proxy:
            opener = urllib.request.build_opener()
        else:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(url, headers={"User-Agent": "NetUtil/1.0"})
        with opener.open(req, timeout=timeout) as resp:
            rtt = (time.perf_counter() - t0) * 1000.0
            return {"ok": True, "status": resp.status, "rtt_ms": round(rtt, 1)}
    except urllib.error.HTTPError as e:
        # 4xx/5xx — сервер ОТВЕТИЛ, значит трафик дошёл. Это успех соединения.
        rtt = (time.perf_counter() - t0) * 1000.0
        return {"ok": True, "status": e.code, "rtt_ms": round(rtt, 1),
                "http_error": True}
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            return {"ok": False, "error": str(e), "ssl_error": True}
        return {"ok": False, "error": str(e)}
    except ssl.SSLCertVerificationError as e:
        # Сервер отвечает, но сертификат не проверяется (напр., Минцифры)
        return {"ok": False, "error": str(e), "ssl_error": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def site_reachable(res: dict, group: str) -> bool:
    """Считаем ли сайт доступным. Для RU игнорируем SSL-ошибку:
    если TCP проходит, а TLS падает с ошибкой сертификата — это требование
    сертификатов Минцифры (которых нет в системе), а не недоступность сайта."""
    tcp_ok = res.get("tcp", {}).get("ok")
    http = res.get("http", {})
    http_d = res.get("http_direct", {})
    if http.get("ok") or http_d.get("ok"):
        return True
    if group == "RU" and tcp_ok and (http.get("ssl_error") or http_d.get("ssl_error")):
        return True
    return False


def ping_test(host: str, timeout=2.0) -> dict:
    """Быстрый ICMP-ping (может не работать у провайдера/на сайтах)."""
    out = run_raw(["ping", "-n", "1", "-w", str(int(timeout * 1000)), host], timeout + 2)
    m = re.search(r"время[=<]\s*(\d+)\s*мс|time[=<]\s*(\d+)\s*ms", out, re.I)
    if m:
        ms = int(m.group(1) or m.group(2))
        return {"ok": True, "rtt_ms": ms}
    if re.search(r"TTL=|ttl=", out, re.I):
        return {"ok": True, "rtt_ms": None}
    return {"ok": False, "error": "нет ответа"}


# ----------------------------------------------------------------------------
# Сбор конфигураций
# ----------------------------------------------------------------------------

def collect_adapters():
    """Адаптеры: таблица из ipconfig + сырой ipconfig."""
    raw = run_raw(["ipconfig", "/all"])
    adapters = parse_ipconfig_adapters(raw)
    rows = []
    for a in adapters:
        rows.append([
            a["name"], a["desc"], a["ipv4"], a["gateway"],
            ", ".join(a["dns"]), a["status"], a["dhcp"],
        ])
    tables = [{
        "name": "Сетевые адаптеры (ipconfig /all)",
        "columns": ["Имя", "Описание", "IPv4", "Шлюз", "DNS", "Состояние", "DHCP"],
        "rows": rows,
    }]
    return {"tables": tables, "text": raw or "[ipconfig /all: пусто]"}


def collect_dns():
    """DNS: глобальные настройки, DoH, NRPT, кэш."""
    tables = []
    text = ""

    g = ps_json("Get-DnsClientGlobalSetting | ConvertTo-Json -Compress")
    if g:
        rows = []
        for key in ("UseSuffixSearchList", "SuffixSearchList", "DevolutionLevel",
                    "UseDevolution"):
            rows.append([key, str(g.get(key, ""))])
        tables.append({
            "name": "Глобальные настройки DNS-клиента",
            "columns": ["Параметр", "Значение"],
            "rows": rows,
        })
        doh = g.get("Doh", None)
        tables.append({
            "name": "DNS over HTTPS (DoH)",
            "columns": ["Параметр", "Значение"],
            "rows": [[k, str(v)] for k, v in (doh or {}).items()] or [["—", "не задан"]],
        })

    nrpt = ps_json("Get-DnsClientNrptPolicy | ConvertTo-Json -Compress")
    rows = []
    if nrpt:
        if isinstance(nrpt, dict):
            nrpt = [nrpt]
        for n in nrpt:
            rows.append([
                n.get("Namespace", ""), n.get("NameServers", ""),
                n.get("DisplayName", ""), str(n.get("Secure", "")),
            ])
    tables.append({
        "name": "Политики разрешения имён (NRPT — часто ломают обходчики)",
        "columns": ["Namespace", "NameServers", "Имя", "Secure"],
        "rows": rows or [["—", "—", "—", "—"]],
    })

    # DNS-кэш резолвера — именно его очищает 'ipconfig /flushdns'
    dns_raw = run_raw(["ipconfig", "/displaydns"]) or ""
    if re.search(r"elevation|повышени|администратор", dns_raw, re.I):
        tables.append({
            "name": "DNS-кэш резолвера (нужны права администратора)",
            "columns": ["Имя", "IP (из кэша)"],
            "rows": [["—", "перезапусти программу от администратора, "
                          "чтобы увидеть кэш"]],
        })
    else:
        cache_records = parse_displaydns(dns_raw)
        suspicious = [r for r in cache_records
                      if any(is_suspicious_cache_ip(ip) for ip in r["ips"])]
        cache_rows = []
        for r in cache_records[:40]:
            cache_rows.append([r["name"], ", ".join(r["ips"])])
        tables.append({
            "name": f"DNS-кэш резолвера: {len(cache_records)} записей "
                    f"(подозрительных: {len(suspicious)}). Очищается: ipconfig /flushdns",
            "columns": ["Имя", "IP (из кэша)"],
            "rows": cache_rows or [["—", "кэш пуст"]],
        })

    text += run_raw(["netsh", "dns", "show", "global"]) or ""
    return {"tables": tables, "text": text}


def collect_routes():
    """Маршруты: шлюзы по умолчанию + метрики + MTU + сырой route print."""
    tables = []
    text = run_raw(["route", "print", "-4"]) or ""
    routes = parse_route_print(text)
    ip_text = run_raw(["ipconfig", "/all"]) or ""
    tunnel_ips = tunnel_interface_ips(parse_ipconfig_adapters(ip_text))
    defaults = [r for r in routes
                if r["network"] == "0.0.0.0" and r["mask"] == "0.0.0.0"]
    defaults.sort(key=lambda r: r["metric"])
    rows = []
    for r in defaults:
        rows.append([
            r["gateway"], r["interface"], str(r["metric"]),
            "туннель" if route_through_tunnel(r, tunnel_ips) else "физический",
        ])
    tables.append({
        "name": "Маршруты по умолчанию (IPv4, отсортированы по метрике)",
        "columns": ["Шлюз", "Интерфейс", "Метрика", "Тип"],
        "rows": rows or [["—", "—", "—", "—"]],
    })

    # capture-маршруты /1../8 — так клиенты (Amnezia и др.) делают полный туннель
    frac, captured = tunnel_traffic_fraction(routes, tunnel_ips)
    cap_rows = []
    for r in sorted(captured, key=lambda x: mask_to_prefix(x["mask"]) or 99):
        cap_rows.append([
            f"{r['network']}/{mask_to_prefix(r['mask'])}",
            r["interface"], str(r["metric"]),
        ])
    if cap_rows:
        tables.append({
            "name": "Маршруты-захваты через туннель (полный туннель, ~%.0f%% адресов)"
                    % (frac * 100),
            "columns": ["Сеть", "Интерфейс", "Метрика"],
            "rows": cap_rows,
        })

    ifc = ps_json(
        "Get-NetIPInterface -AddressFamily IPv4 | "
        "Select-Object InterfaceAlias,InterfaceMetric,Dhcp,NlMtu "
        "| ConvertTo-Json -Compress")
    rows = []
    if ifc:
        if isinstance(ifc, dict):
            ifc = [ifc]
        for i in ifc:
            rows.append([
                i.get("InterfaceAlias", ""), str(i.get("InterfaceMetric", "")),
                str(i.get("Dhcp", "")), str(i.get("NlMtu", "")),
            ])
    tables.append({
        "name": "Интерфейсы IPv4 (метрика / MTU, через Get-NetIPInterface)",
        "columns": ["Адаптер", "Метрика", "DHCP", "MTU"],
        "rows": rows,
    })
    return {"tables": tables, "text": text}


def collect_proxy():
    """Прокси: WinINET (реестр), WinHTTP, переменные окружения."""
    tables = []
    text = ""

    import winreg  # noqa: PLC0415
    rows = []
    try:
        k = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        vals = {}
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride",
                     "AutoConfigURL", "AutoDetect", "MigrateProxy"):
            try:
                vals[name] = str(winreg.QueryValueEx(k, name)[0])
            except FileNotFoundError:
                vals[name] = ""
        winreg.CloseKey(k)
        rows = [[n, v] for n, v in vals.items()]
    except Exception as e:  # noqa: BLE001
        rows = [["ошибка", str(e)]]
    tables.append({
        "name": "Системный прокси (WinINET, реестр HKCU)",
        "columns": ["Параметр", "Значение"],
        "rows": rows,
    })
    text += run_raw(["netsh", "winhttp", "show", "proxy"]) or ""

    env = {k: v for k, v in os.environ.items()
           if k.lower() in ("http_proxy", "https_proxy", "all_proxy",
                            "no_proxy", "ftp_proxy")}
    tables.append({
        "name": "Прокси из переменных окружения",
        "columns": ["Переменная", "Значение"],
        "rows": [[k, v] for k, v in env.items()] or [["—", "не заданы"]],
    })
    return {"tables": tables, "text": text}


def collect_hosts():
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    text = ""
    entries = []
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    entries.append(s)
        text = "\n".join(entries) or "(нет активных записей, кроме комментариев)"
    except Exception as e:  # noqa: BLE001
        text = f"[не удалось прочитать hosts: {e}]"
    return {"tables": [{
        "name": "Активные записи в hosts",
        "columns": ["Строка"],
        "rows": [[e] for e in entries] or [["—"]],
    }], "text": f"Файл: {hosts_path}"}


def collect_processes():
    """VPN-процессы (tasklist) и службы (состояние словами)."""
    tables = []

    # --- процессы: два источника (tasklist и Get-Process), поиск по имени И пути ---
    seen = {}
    tl = run_raw(["tasklist", "/fo", "csv", "/nh"])
    for line in tl.splitlines():
        parts = line.split('","')
        if len(parts) < 2:
            continue
        name = parts[0].strip('"')
        pid = parts[1].strip('"')
        if any(pat in name.lower() for pat in VPN_PROCESS_PATTERNS):
            seen[pid] = [pid, name, ""]
    procs = ps_json("Get-Process | Select-Object Id,ProcessName,Path "
                    "| ConvertTo-Json -Compress")
    if procs:
        if isinstance(procs, dict):
            procs = [procs]
        for p in procs:
            pid = str(p.get("Id", ""))
            name = p.get("ProcessName", "") or ""
            path = p.get("Path", "") or ""
            if any(pat in name.lower() or pat in path.lower()
                   for pat in VPN_PROCESS_PATTERNS):
                if pid in seen:
                    seen[pid][2] = path
                else:
                    seen[pid] = [pid, name, path]
    rows = sorted(seen.values(), key=lambda r: r[0])
    tables.append({
        "name": "Запущенные VPN/прокси-процессы",
        "columns": ["PID", "Процесс", "Путь"],
        "rows": rows or [["—", "—", "—"]],
    })

    # --- службы с человекочитаемым состоянием ---
    svcs = ps_json("Get-Service | Select-Object Name,DisplayName,Status,StartType "
                   "| ConvertTo-Json -Compress")
    rows = []
    if svcs:
        if isinstance(svcs, dict):
            svcs = [svcs]
        for s in svcs:
            name = (s.get("Name") or "").lower()
            disp = (s.get("DisplayName") or "").lower()
            if any(pat in name or pat in disp for pat in VPN_SERVICE_PATTERNS):
                st, tt = s.get("Status"), s.get("StartType")
                try:
                    st = int(st)
                except (TypeError, ValueError):
                    st = None
                try:
                    tt = int(tt)
                except (TypeError, ValueError):
                    tt = None
                rows.append([
                    s.get("Name", ""), s.get("DisplayName", ""),
                    SERVICE_STATUS_MAP.get(st, str(st)),
                    SERVICE_START_MAP.get(tt, str(tt)),
                ])
    tables.append({
        "name": "Службы VPN-инструментов",
        "columns": ["Имя", "Отображаемое имя", "Состояние", "Тип запуска"],
        "rows": rows or [["—", "—", "—", "—"]],
    })
    return {"tables": tables}


def collect_firewall():
    """Правила брандмауэра, относящиеся к VPN-инструментам + состояние профилей."""
    tables = []
    prof = ps_json(
        "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,"
        "DefaultOutboundAction | ConvertTo-Json -Compress")
    rows = []
    if prof:
        if isinstance(prof, dict):
            prof = [prof]
        for p in prof:
            rows.append([
                translate_val(p.get("Name", ""), FIREWALL_PROFILE_MAP),
                translate_val(str(p.get("Enabled", "")), FIREWALL_ENABLED_MAP),
                translate_val(p.get("DefaultInboundAction", ""), FIREWALL_ACTION_MAP),
                translate_val(p.get("DefaultOutboundAction", ""), FIREWALL_ACTION_MAP),
            ])
    tables.append({
        "name": "Профили брандмауэра",
        "columns": ["Профиль", "Включён", "Входящие по умолч.", "Исходящие по умолч."],
        "rows": rows,
    })

    rules = ps_json(
        "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} | "
        "Select-Object DisplayName,Direction,Action,Profile "
        "| ConvertTo-Json -Compress")
    rows = []
    if rules:
        if isinstance(rules, dict):
            rules = [rules]
        for r in rules:
            disp = (r.get("DisplayName") or "").lower()
            if any(pat in disp for pat in VPN_PROCESS_PATTERNS):
                rows.append([
                    r.get("DisplayName", ""),
                    translate_val(r.get("Direction", ""), FIREWALL_DIRECTION_MAP),
                    translate_val(r.get("Action", ""), FIREWALL_ACTION_MAP),
                    translate_val(r.get("Profile", ""), FIREWALL_PROFILE_MAP),
                ])
    tables.append({
        "name": "Включённые правила брандмауэра, связанные с VPN",
        "columns": ["Имя правила", "Направление", "Действие", "Профиль"],
        "rows": rows or [["—", "—", "—", "—"]],
    })
    return {"tables": tables}


def collect_winsock_tcp():
    """Winsock LSP-каталог (анализ) + глобальные настройки TCP."""
    catalog_text = run_raw(["netsh", "winsock", "show", "catalog"]) or ""
    providers = parse_winsock_catalog(catalog_text)
    base = [p for p in providers
            if "базовый" in p["type"].lower() or "base" in p["type"].lower()]
    ns = [p for p in providers
          if "пространств" in p["type"].lower() or "namespace" in p["type"].lower()]
    third = [p for p in base
             if p["path"] and "system32" not in p["path"].lower()]

    tables = [{
        "name": "Каталог Winsock — сводка (netsh winsock reset возвращает к стандартному)",
        "columns": ["Метрика", "Значение"],
        "rows": [
            ["Базовых провайдеров (LSP)", str(len(base))],
            ["Провайдеров пространств имён", str(len(ns))],
            ["Сторонних (не Microsoft)", str(len(third))],
        ],
    }]
    if third:
        tables.append({
            "name": "Сторонние LSP-провайдеры (сбрасываются командой netsh winsock reset)",
            "columns": ["Тип", "Описание", "Путь"],
            "rows": [[p["type"], p["desc"], p["path"]] for p in third],
        })

    text = catalog_text
    text += "\n\n" + (run_raw(["netsh", "int", "tcp", "show", "global"]) or "")
    text += "\n\n" + (run_raw(["netsh", "interface", "tcp", "show", "heuristics"]) or "")
    return {"tables": tables, "text": text}


def collect_listeners():
    """Слушающие порты (остаточные прокси) и PID->процесс."""
    tables = []
    pid_name = {}
    # tasklist работает без WMI/прав администратора
    tl = run_raw(["tasklist", "/fo", "csv", "/nh"])
    for line in tl.splitlines():
        parts = line.split('","')
        if len(parts) >= 2:
            pid_name[parts[1].strip('"')] = parts[0].strip('"')
    procs = ps_json("Get-Process | Select-Object Id,ProcessName "
                    "| ConvertTo-Json -Compress")
    if procs:
        if isinstance(procs, dict):
            procs = [procs]
        for p in procs:
            pid_name.setdefault(str(p.get("Id")), p.get("ProcessName", ""))

    out = run_raw(["netstat", "-ano", "-p", "tcp"])
    rows = []
    for line in out.splitlines():
        if "LISTENING" not in line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        local, pid = parts[1], parts[-1]
        proc = pid_name.get(pid, "?")
        if local.startswith("127.0.0.1") or local.startswith("[::1]") or \
                local.startswith("0.0.0.0"):
            rows.append([local, pid, proc])
    tables.append({
        "name": "Слушающие TCP-порты (локальные прокси/сервисы)",
        "columns": ["Локальный адрес:порт", "PID", "Процесс"],
        "rows": rows,
    })
    return {"tables": tables}


SECTIONS = [
    ("Адаптеры", collect_adapters),
    ("DNS", collect_dns),
    ("Маршруты / MTU", collect_routes),
    ("Прокси", collect_proxy),
    ("hosts", collect_hosts),
    ("Процессы / Службы", collect_processes),
    ("Брандмауэр", collect_firewall),
    ("Порты (netstat)", collect_listeners),
    ("Winsock / TCP", collect_winsock_tcp),
]


def collect_all():
    """Собрать все секции, вернуть словарь + список находок (findings)."""
    data = {}
    for title, fn in SECTIONS:
        try:
            data[title] = fn()
        except Exception as e:  # noqa: BLE001
            data[title] = {"tables": [], "text": f"[сбой сбора: {e}]"}
    findings = analyze(data)
    return data, findings


def analyze(data):
    """Эвристики: вернуть список (severity, message)."""
    findings = []
    add = lambda sev, msg: findings.append((sev, msg))  # noqa: E731

    # --- маршруты по умолчанию (самое важное) ---
    route_text = data.get("Маршруты / MTU", {}).get("text", "") or ""
    if route_text:
        defaults = [r for r in parse_route_print(route_text)
                    if r["network"] == "0.0.0.0" and r["mask"] == "0.0.0.0"]
        if defaults:
            defaults.sort(key=lambda r: r["metric"])
            best = defaults[0]
            desc = "; ".join(
                f"{r['gateway']} -> {r['interface']} (метрика {r['metric']})"
                for r in defaults)
            tunnel_routes = [r for r in defaults
                             if r["gateway"].lower() in ("on-link", "связанный")
                             or is_tunnel_ip(r["interface"])]
            if len(defaults) > 1 and tunnel_routes and best in tunnel_routes:
                add("error",
                    f"Маршрут по умолчанию уходит в туннель: "
                    f"{best['gateway']} -> {best['interface']} (метрика "
                    f"{best['metric']}) — приоритетнее физического шлюза. "
                    f"ВЕСЬ трафик идёт через VPN-туннель, даже если VPN "
                    f"«отключён». Все шлюзы: {desc}")
            elif len(defaults) > 1:
                add("warn", f"Несколько маршрутов по умолчанию: {desc}. "
                            f"Проверь метрики — трафик может уходить не туда.")
            elif is_tunnel_ip(best["interface"]) or \
                    best["gateway"].lower() in ("on-link", "связанный"):
                add("warn",
                    f"Единственный маршрут по умолчанию идёт через туннель "
                    f"({best['interface']}). Без поднятого туннеля интернет "
                    f"не заработает.")

    # --- виртуальные адаптеры и туннельный DNS (из ipconfig) ---
    ip_text = data.get("Адаптеры", {}).get("text", "") or ""
    adapters = parse_ipconfig_adapters(ip_text)
    for a in adapters:
        low = (a["name"] + " " + a["desc"]).lower()
        if any(pat in low for pat in VPN_ADAPTER_PATTERNS):
            add("warn", f"Найден виртуальный/туннельный адаптер «{a['name']}» "
                        f"({a['desc']}). Остаточные TUN/TAP/WireGuard-адаптеры "
                        f"часто ломают маршрутизацию.")
        elif any(pat in low for pat in VM_ADAPTER_PATTERNS):
            add("info", f"Адаптер виртуальной машины «{a['name']}» "
                        f"({a['desc']}) — обычно безвреден.")
        if a.get("unknown"):
            add("info", f"Адаптер «{a['name']}» помечен как «неизвестный» — "
                        f"обычно это скрытый/остаточный драйвер.")
        for dns in a["dns"]:
            d = dns.split("(")[0].strip()
            if is_tunnel_ip(d) or d.startswith("10.") or d.startswith("127."):
                add("warn", f"DNS на адаптере «{a['name']}» указывает на "
                            f"туннельный/локальный резолвер {d}. Если туннель "
                            f"выключен — DNS перестанет работать.")

    # --- прокси ---
    if "Прокси" in data:
        sec = data["Прокси"]
        for t in sec.get("tables", []):
            if t.get("name", "").startswith("Системный прокси"):
                d = {r[0]: r[1] for r in t.get("rows", []) if len(r) >= 2}
                if d.get("ProxyEnable") == "1":
                    server = d.get("ProxyServer", "?")
                    if "127.0.0.1" in server or "localhost" in server:
                        add("warn", f"Системный прокси включён и указывает на "
                                    f"локальный порт: {server}. Если прокси-клиент "
                                    f"выключен — приложения останутся без интернета.")
                    else:
                        add("warn", f"Системный прокси включён: {server}")
                if d.get("AutoConfigURL"):
                    add("info", f"Настроен PAC-скрипт: {d.get('AutoConfigURL')}")

    # --- NRPT ---
    if "DNS" in data:
        sec = data["DNS"]
        for t in sec.get("tables", []):
            if "NRPT" in t.get("name", ""):
                real = [r for r in t.get("rows", []) if r[0] != "—"]
                if real:
                    add("warn", "Обнаружены NRPT-политики разрешения имён — их "
                                "оставляют VPN-клиенты, они часто ломают DNS.")

    # --- hosts ---
    if "hosts" in data:
        sec = data["hosts"]
        for t in sec.get("tables", []):
            real = [r for r in t.get("rows", []) if r[0] != "—"]
            if real:
                add("info", f"В hosts есть активные записи ({len(real)} шт.) — "
                            f"проверь, что они намеренные (вкладка hosts).")

    # --- DNS-кэш (с чем работает ipconfig /flushdns) ---
    if "DNS" in data:
        for t in data["DNS"].get("tables", []):
            if "DNS-кэш" in t.get("name", ""):
                real = [r for r in t.get("rows", []) if r[0] != "—"]
                sus = 0
                for r in real:
                    if len(r) > 1 and any(is_suspicious_cache_ip(ip)
                                          for ip in str(r[1]).split(", ")):
                        sus += 1
                if sus:
                    add("warn", f"В DNS-кэше {sus} записей разрешаются в "
                                f"подозрительные адреса (loopback/частные). "
                                f"ipconfig /flushdns очистит кэш и заставит "
                                f"переразрешить имена.")
                elif real:
                    add("info", f"DNS-кэш: {len(real)} записей, подозрительных "
                                f"не найдено.")

    # --- Winsock (с чем работает netsh winsock reset) ---
    if "Winsock / TCP" in data:
        txt = data["Winsock / TCP"].get("text", "") or ""
        providers = parse_winsock_catalog(txt)
        base = [p for p in providers
                if "базовый" in p["type"].lower() or "base" in p["type"].lower()]
        third = [p for p in base
                 if p["path"] and "system32" not in p["path"].lower()]
        if third:
            add("warn", f"Winsock: обнаружено {len(third)} сторонних "
                        f"LSP-провайдера (не Microsoft). netsh winsock reset "
                        f"вернёт каталог к стандартному (нужна перезагрузка).")
        elif base:
            add("info", f"Winsock: каталог стандартный ({len(base)} базовых "
                        f"провайдеров), сторонних LSP нет.")

    return findings


def determine_status(data):
    """Определить СОСТОЯНИЯ системы по внешним признакам (короткие вердикты)."""
    items = []
    adapters = parse_ipconfig_adapters(data.get("Адаптеры", {}).get("text", "") or "")
    tunnel_adapters = [a for a in adapters
                       if any(pat in (a["name"] + " " + a["desc"]).lower()
                              for pat in VPN_ADAPTER_PATTERNS)]
    active_tunnel = [a for a in tunnel_adapters if a["ipv4"]]

    route_text = data.get("Маршруты / MTU", {}).get("text", "") or ""
    routes = parse_route_print(route_text)
    tunnel_ips = tunnel_interface_ips(adapters)
    frac, _captured = tunnel_traffic_fraction(routes, tunnel_ips)
    default_tunnel = [r for r in routes
                      if r["network"] == "0.0.0.0" and r["mask"] == "0.0.0.0"
                      and route_through_tunnel(r, tunnel_ips)]

    # VPN/туннель
    if active_tunnel and (frac >= 0.5 or default_tunnel):
        items.append({"id": "vpn", "label": "VPN/туннель",
                      "value": "Активен", "severity": "ok"})
    elif active_tunnel:
        items.append({"id": "vpn", "label": "VPN/туннель",
                      "value": "Адаптер поднят, без маршрута", "severity": "warn"})
    elif tunnel_adapters:
        items.append({"id": "vpn", "label": "VPN/туннель",
                      "value": "Выключен (остался адаптер)", "severity": "warn"})
    else:
        items.append({"id": "vpn", "label": "VPN/туннель",
                      "value": "Выключен", "severity": "neutral"})

    # Маршрутизация (как реально идёт трафик)
    if frac >= 0.5 or default_tunnel:
        items.append({"id": "route", "label": "Маршрутизация",
                      "value": "Через туннель", "severity": "ok"})
    elif frac > 0:
        items.append({"id": "route", "label": "Маршрутизация",
                      "value": "Частично через туннель", "severity": "warn"})
    else:
        items.append({"id": "route", "label": "Маршрутизация",
                      "value": "Напрямую", "severity": "neutral"})

    # Системный прокси
    proxy_on, proxy_server = False, ""
    for t in data.get("Прокси", {}).get("tables", []):
        if t.get("name", "").startswith("Системный прокси"):
            d = {r[0]: r[1] for r in t.get("rows", []) if len(r) >= 2}
            if d.get("ProxyEnable") == "1":
                proxy_on, proxy_server = True, d.get("ProxyServer", "")
    if proxy_on:
        items.append({"id": "proxy", "label": "Системный прокси",
                      "value": "Включён (%s)" % proxy_server, "severity": "warn"})
    else:
        items.append({"id": "proxy", "label": "Системный прокси",
                      "value": "Выключен", "severity": "neutral"})

    # DNS-кэш
    cache_sus, cache_elev = 0, False
    for t in data.get("DNS", {}).get("tables", []):
        if "DNS-кэш" in t.get("name", ""):
            for r in t.get("rows", []):
                if len(r) > 1 and str(r[1]).startswith("перезапусти"):
                    cache_elev = True
                elif len(r) > 1 and r[0] != "—":
                    if any(is_suspicious_cache_ip(ip)
                           for ip in str(r[1]).split(", ")):
                        cache_sus += 1
    if cache_elev:
        items.append({"id": "cache", "label": "DNS-кэш",
                      "value": "нужны права админа", "severity": "neutral"})
    elif cache_sus:
        items.append({"id": "cache", "label": "DNS-кэш",
                      "value": "%d подозр." % cache_sus, "severity": "warn"})
    else:
        items.append({"id": "cache", "label": "DNS-кэш",
                      "value": "Чистый", "severity": "ok"})

    # Winsock (LSP)
    providers = parse_winsock_catalog(
        data.get("Winsock / TCP", {}).get("text", "") or "")
    base = [p for p in providers
            if "базовый" in p["type"].lower() or "base" in p["type"].lower()]
    third = [p for p in base
             if p["path"] and "system32" not in p["path"].lower()]
    if third:
        items.append({"id": "winsock", "label": "Winsock (LSP)",
                      "value": "%d сторонних" % len(third), "severity": "warn"})
    elif base:
        items.append({"id": "winsock", "label": "Winsock (LSP)",
                      "value": "Стандартный", "severity": "ok"})
    else:
        items.append({"id": "winsock", "label": "Winsock (LSP)",
                      "value": "н/д", "severity": "neutral"})

    # Виртуальные адаптеры
    if tunnel_adapters:
        active_n = len(active_tunnel)
        leftover_n = len(tunnel_adapters) - active_n
        if leftover_n:
            items.append({"id": "adapters", "label": "Вирт. адаптеры",
                          "value": "%d шт (%d активн., %d остаточн.)"
                                   % (len(tunnel_adapters), active_n, leftover_n),
                          "severity": "warn"})
        else:
            items.append({"id": "adapters", "label": "Вирт. адаптеры",
                          "value": "%d шт (активные)" % len(tunnel_adapters),
                          "severity": "neutral"})
    else:
        items.append({"id": "adapters", "label": "Вирт. адаптеры",
                      "value": "Нет", "severity": "ok"})

    return items


def dns_resolution_check():
    """Корректность резолвинга напрямую (в обход кэша Windows)."""
    verdicts = []
    for server in ("1.1.1.1", "8.8.8.8"):
        r = dns_udp_query(server, "example.com", timeout=3)
        if r.get("ok"):
            if r.get("ips") and not any(is_suspicious_cache_ip(i)
                                        for i in r["ips"]):
                verdicts.append("ok")
            else:
                verdicts.append("poison")
        else:
            verdicts.append("fail")
    if "ok" in verdicts:
        return {"state": "ok", "value": "Корректен"}
    if "poison" in verdicts:
        return {"state": "poison", "value": "Подменяется"}
    return {"state": "fail", "value": "Блокируется (UDP/53)"}


# Домены, которые в РФ блокируются на уровне DNS (для проверки цензуры)
DNS_CENSORED_DOMAINS = ["instagram.com", "facebook.com"]


def doh_query(domain: str, server: str = "1.1.1.1", timeout=6.0):
    """DNS over HTTPS (зашифрован — «чистый» контрольный ответ, не перехватывается)."""
    try:
        url = "https://%s/dns-query?name=%s&type=A" % (server, domain)
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json", "User-Agent": "NetUtil/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        ips = [a["data"] for a in data.get("Answer", [])
               if a.get("type") == 1]
        return {"ok": True, "ips": ips}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def dns_whoami():
    """Какой резолвер фактически отвечает (и его IP) — приём whoami.*."""
    for name in ("whoami.akamai.net", "whoami.cloudflare.com"):
        r = resolve_host(name)
        if r.get("ok") and r.get("ips"):
            return {"host": name, "ips": r["ips"]}
    return None


def dns_censorship_verdict(checks):
    """Вердикт по DNS-цензуре: блокировка / подмена / чисто."""
    for c in checks:
        # система не резолвит, а DoH резолвит -> блокировка домена на DNS
        if not c["system_ok"] and c["doh_ok"] and c["doh_ips"]:
            return {"state": "blocked", "value": "Блокирует (%s)" % c["domain"]}
        # система вернула подозрительный IP (0.0.0.0/частный/loopback) -> подмена
        if c["system_ok"] and any(is_suspicious_cache_ip(i)
                                  for i in c["system_ips"]):
            return {"state": "poison", "value": "Подмена (%s)" % c["domain"]}
    return {"state": "clean", "value": "Не фильтруется"}


def dns_analysis():
    """Полный анализ DNS: корректность, резолвер/страна, цензура."""
    out = {}
    out["direct"] = dns_resolution_check()
    who = dns_whoami()
    out["whoami"] = who
    out["resolver_geo"] = get_ip_geo(who["ips"][0]) if who and who.get("ips") else None

    checks = []
    for dom in DNS_CENSORED_DOMAINS:
        sysr = resolve_host(dom)
        doh = doh_query(dom)
        checks.append({
            "domain": dom,
            "system_ok": sysr.get("ok"),
            "system_ips": sysr.get("ips", []),
            "doh_ok": doh.get("ok"),
            "doh_ips": doh.get("ips", []),
        })
    out["checks"] = checks
    out["censorship"] = dns_censorship_verdict(checks)
    return out


def vpn_quality_verdict(zone_state):
    """Оценить качество включённого VPN по АБСОЛЮТНОЙ скорости туннеля.
    Не сравниваем с прямым соединением — туннель всегда медленнее."""
    st = zone_state.get("Зарубежные", {})
    speed, speed_ok = st.get("speed"), st.get("speed_ok")
    lats = st.get("lats", [])
    lat = sorted(lats)[len(lats) // 2] if lats else None
    lat_s = (" · %d мс" % lat) if lat else ""

    if speed is None:
        return "проверяется…", "neutral"
    if not speed_ok:
        return "Туннель не пропускает трафик", "bad"
    try:
        mbps = float(speed)
    except (TypeError, ValueError):
        return "н/д", "neutral"

    base = "%.1f Мбит/с%s" % (mbps, lat_s)
    if mbps < 1.0:
        return "Критически низкая скорость (%s)" % base, "bad"
    if mbps < 5.0:
        return "Сильно режется (%s)" % base, "bad"
    if mbps < 15:
        return "Медленно (%s)" % base, "warn"
    return "В порядке (%s)" % base, "ok"


def split_tunneling_status(zone_ips, vpn_active, egress=None):
    """Вердикт: работает ли split-tunneling (RU напрямую, зарубеж через туннель).
    Основной сигнал — внешний IP: RU-echo ≠ зарубежный echo (правильно для
    TUN-сплита sing-box/Happ). Локальный путь (egress) — запасной, для
    WireGuard/AmneziaWG, где маршрутизация IP-уровневая."""
    if not vpn_active:
        return "VPN выключен", "neutral"
    ru_ip = zone_ips.get("RU")
    fo_ip = zone_ips.get("Зарубежные")
    if ru_ip and fo_ip and ru_ip != fo_ip:
        return "Активен (RU -> %s, зарубеж -> %s)" % (ru_ip, fo_ip), "ok"
    # запасной: локальный путь (IP-маршрутизация)
    if egress:
        ru = egress.get("RU") or {}
        fo = egress.get("Зарубежные") or {}
        if ru.get("path") == "напрямую" and fo.get("path") == "туннель":
            return "Активен (RU напрямую)", "ok"
    if fo_ip and ru_ip == fo_ip:
        return "Нет (полный туннель)", "neutral"
    return "не определён", "neutral"


def zone_status(ok: int, total: int):
    """Статус зоны: доступно при >= 80%, недоступно при < 50%, иначе частично."""
    if total == 0:
        return "—", "neutral"
    ratio = ok / total
    if ratio >= 0.8:
        return "ДОСТУПНО", "ok"
    if ratio < 0.5:
        return "НЕДОСТУПНО", "bad"
    return "ЧАСТИЧНО", "warn"


def vpn_diagnosis(zone_state, vpn_active):
    """Эвристический диагноз VPN по доступности зон.

    zone_state: {зона: {"ok": int, "total": int}}
    vpn_active: поднят ли туннель.
    Возвращает {"value", "severity"} или None (если всё в порядке / нет данных).
    """
    def ratio(z):
        st = zone_state.get(z) or {}
        total = st.get("total") or 0
        if not total:
            return None
        return st.get("ok", 0) / total

    ru = ratio("RU")
    fo = ratio("Зарубежные")
    bl = ratio("Заблокированные")
    if ru is None or fo is None or bl is None:
        return None  # данных ещё нет

    half = 0.5

    if not vpn_active:
        if bl < half:
            return {"value": "VPN выключен (заблокированные недоступны — "
                              "это ожидаемо)", "severity": "neutral"}
        return None

    # туннель поднят
    if ru < half and fo < half:
        return {"value": "VPN откис: туннель поднят, но ни RU, ни обычные "
                          "зарубежные не открываются — меняй локацию/провайдера",
                "severity": "bad"}
    if ru < half:
        return {"value": "Проблема split-tunneling: зарубежные и "
                          "заблокированные работают, а RU не идёт напрямую",
                "severity": "bad"}
    if fo < half:
        return {"value": "VPN не пропускает обычные зарубежные — меняй "
                          "локацию/провайдера", "severity": "bad"}
    if bl < half:
        return {"value": "VPN не обходит блокировки: RU и зарубежные в норме, "
                          "а заблокированные не открываются",
                "severity": "bad"}
    return None


# ----------------------------------------------------------------------------
# Онлайн-тесты
# ----------------------------------------------------------------------------

def run_site_test(name, url, timeout=5.0):
    host = urllib.parse.urlparse(url).netloc
    res = {"name": name, "host": host, "url": url}
    t0 = time.perf_counter()
    dns = resolve_host(host, timeout=timeout)
    dns["rtt_ms"] = round((time.perf_counter() - t0) * 1000.0, 1)
    res["dns"] = dns
    if not dns.get("ok"):
        # DNS не ответил — дальше по этому сайту идти незачем
        res["tcp"] = {"ok": False, "error": dns.get("error", "DNS")}
        res["http"] = {"ok": False, "error": dns.get("error", "DNS")}
        res["http_direct"] = {"ok": False, "error": dns.get("error", "DNS")}
        return res
    # берём IPv4 для «честного» TCP-пинга (без повторного DNS)
    ip = None
    if dns.get("ok") and dns.get("ips"):
        for i in dns["ips"]:
            if ":" not in i:
                ip = i
                break
    res["tcp"] = tcp_test(host, 443, ip=ip, timeout=min(timeout, 3.5))
    res["http"] = http_test(url, use_system_proxy=True, timeout=timeout)
    res["http_direct"] = http_test(url, use_system_proxy=False, timeout=timeout)
    return res


def run_dns_server_test(server, host="example.com"):
    r = dns_udp_query(server, host)
    r["server"] = server
    return r


# ----------------------------------------------------------------------------
# UDP-диагностика (игровой трафик: Elite Dangerous и т.п.)
# ----------------------------------------------------------------------------
# Одинаковые методы: STUN (3478) + NTP (123) + DNS (53), отличаются только
# адреса. QUIC (UDP 443) не используем — конфликтует с Xray.
#
# Почему нет отдельной зоны «Заблокированные»: UDP в РФ не блокируется —
# блокировка на уровне TCP/SNI (и частично QUIC, который не прокидывает
# Xray). Любой STUN/NTP-сервер через тот же путь даёт те же цифры, что
# «Зарубежные», поэтому отдельная строка была бы дублем и ложным «всё ок».
UDP_TARGETS = {
    "RU": [
        ("STUN Sipnet", "stun.sipnet.ru", 3478, "stun"),
        ("NTP VNIIFTRI", "ntp1.vniiftri.ru", 123, "ntp"),
        ("DNS Яндекс", "77.88.8.8", 53, "dns"),
    ],
    "Зарубежные": [
        ("STUN Cloudflare", "stun.cloudflare.com", 3478, "stun"),
        ("NTP Google", "time.google.com", 123, "ntp"),
        ("DNS Cloudflare", "1.1.1.1", 53, "dns"),
    ],
}


def _stun_binding_request():
    """STUN Binding Request (RFC 5389), 20 байт."""
    return b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12)


def _ntp_request():
    """NTP client (mode 3), 48 байт."""
    return b"\x1b" + b"\x00" * 47


def _dns_request():
    """DNS A-запрос для example.com (UDP/53)."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode("ascii")
                 for p in "example.com".split(".") if p) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)


def _quic_probe_request():
    """QUIC long-header с неподдерживаемой версией (>=1200 байт).

    Сервер отвечает Version Negotiation — значит UDP/443 до него доходит.
    """
    dcid = os.urandom(8)
    scid = os.urandom(8)
    hdr = (b"\xc0" + b"\xfa\x1a\x2a\x3a" + bytes([len(dcid)]) + dcid +
           bytes([len(scid)]) + scid)
    return hdr + os.urandom(1200 - len(hdr))


def udp_probe(host, port, kind="stun", timeout=1.5, attempts=3):
    """Шлёт UDP-пробы и считает RTT/потери. kind: stun | ntp | dns."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET,
                                   socket.SOCK_DGRAM)
        ip = infos[0][4][0]
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": "DNS: %s" % e,
                "sent": 0, "recv": 0, "loss": 100.0}
    sent = recv = 0
    rtts = []
    for _ in range(attempts):
        sent += 1
        if kind == "stun":
            payload = _stun_binding_request()
        elif kind == "dns":
            payload = _dns_request()
        elif kind == "quic":
            payload = _quic_probe_request()
        else:
            payload = _ntp_request()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            t0 = time.perf_counter()
            s.sendto(payload, (ip, port))
            s.recvfrom(2048)
            rtt = (time.perf_counter() - t0) * 1000.0
            s.close()
            rtts.append(rtt)
            recv += 1
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.05)
    loss = (sent - recv) * 100.0 / sent if sent else 100.0
    if rtts:
        return {"ok": True, "ip": ip, "sent": sent, "recv": recv,
                "loss": round(loss, 1),
                "rtt_ms": round(sum(rtts) / len(rtts), 1),
                "rtt_min": round(min(rtts), 1),
                "rtt_max": round(max(rtts), 1)}
    return {"ok": False, "ip": ip, "sent": sent, "recv": 0, "loss": 100.0,
            "error": "нет ответа"}


def udp_zone_test(zone):
    """UDP-качество зоны: агрегирует пробы по целям (разные порты)."""
    targets = UDP_TARGETS.get(zone) or []
    if not targets:
        return {"ok": False, "error": "нет целей", "results": []}
    results = []
    for name, host, port, kind in targets:
        r = udp_probe(host, port, kind)
        r.update({"name": name, "host": host, "port": port})
        results.append(r)
    ok_results = [r for r in results if r.get("ok")]
    if not ok_results:
        return {"ok": False, "error": "UDP не отвечает", "results": results}
    total_sent = sum(r.get("sent", 0) for r in results)
    total_recv = sum(r.get("recv", 0) for r in results)
    loss = ((total_sent - total_recv) * 100.0 / total_sent
            if total_sent else 100.0)
    rtts = [r["rtt_ms"] for r in ok_results]
    ports = sorted({r["port"] for r in ok_results})
    return {"ok": True, "rtt_ms": round(sum(rtts) / len(rtts), 1),
            "loss": round(loss, 1), "ports": ports, "results": results}


def speed_test(url, duration=5.0, workers=4, timeout=20.0):
    """Замер скорости (Мбит/с): несколько параллельных TCP-потоков, скачиваем
    duration секунд. Параллельность критична: на высоком пинге один поток
    (TCP slow-start + handshake) сильно занижает реальную скорость.
    url может быть списком — перебираем, пока не получим результат."""
    urls = [url] if isinstance(url, str) else list(url)
    last = {"ok": False, "error": "нет URL", "bytes": 0}
    for u in urls:
        last = _speed_once(u, duration, workers, timeout)
        if last.get("ok"):
            return last
    return last


def _speed_once(url, duration, workers, timeout):
    total = [0]
    lock = threading.Lock()
    start = time.perf_counter()
    deadline = start + duration

    def worker():
        try:
            opener = urllib.request.build_opener()
            req = urllib.request.Request(url, headers={"User-Agent": "NetUtil/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                while time.perf_counter() < deadline:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    with lock:
                        total[0] += len(chunk)
        except Exception:  # noqa: BLE001
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker) for _ in range(workers)]
        for f in as_completed(futs):
            try:
                f.result()
            except Exception:  # noqa: BLE001
                pass

    dt = time.perf_counter() - start
    b = total[0]
    if dt <= 0 or b < 500_000:
        return {"ok": False, "error": "мало данных", "bytes": b}
    mbps = (b * 8) / (dt * 1_000_000)
    return {"ok": True, "mbps": round(mbps, 1), "bytes": b,
            "seconds": round(dt, 2)}


def get_zone_ips(timeout=8.0):
    """IP, который видят серверы каждой зоны (через echo-сервисы).
    При split-роутинге RU и зарубежный IP будут различаться."""
    result = {}
    tasks = [(z, url) for z, urls in ECHO_SERVERS.items() for url in urls]

    def _fetch(item):
        zone, url = item
        try:
            opener = urllib.request.build_opener()
            req = urllib.request.Request(url, headers={"User-Agent": "NetUtil/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(12000).decode("utf-8", "replace").strip()
            cand = body
            if url.endswith("format=json"):
                cand = json.loads(body).get("ip", body)
            m4 = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", cand or "")
            m6 = re.search(r"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}", cand or "")
            if m4:
                return zone, m4.group(0)
            if m6:
                return zone, m6.group(0)
            return zone, None
        except Exception:  # noqa: BLE001
            return zone, None

    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        for zone, ip in ex.map(_fetch, tasks):
            if ip and result.get(zone) is None:
                result[zone] = ip
    return result


def get_ip_geo(ip: str, timeout=8.0):
    """Геолокация IP (страна/город/ASN) через внешний сервис."""
    if not ip or ":" in ip:
        return None
    urls = [
        ("ipwho", "https://ipwho.is/" + ip),
        ("ipinfo", "https://ipinfo.io/" + ip + "/json"),
    ]
    for kind, url in urls:
        try:
            opener = urllib.request.build_opener()
            req = urllib.request.Request(url, headers={"User-Agent": "NetUtil/1.0"})
            with opener.open(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if kind == "ipwho":
                if data.get("success") is False:
                    continue
                conn = data.get("connection") or {}
                asn = conn.get("asn", "") or data.get("asn", "")
                if isinstance(asn, int):
                    asn = "AS%d" % asn
                return {
                    "country": data.get("country", ""),
                    "country_code": data.get("country_code", ""),
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "asn": asn,
                    "org": conn.get("org", "") or data.get("org", ""),
                }
            else:  # ipinfo
                if "country" not in data:
                    continue
                org = data.get("org", "") or ""
                asn = org.split(" ")[0] if org.startswith("AS") else ""
                return {
                    "country": data.get("country", ""),
                    "country_code": data.get("country", ""),
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "asn": asn,
                    "org": org,
                }
        except Exception:  # noqa: BLE001
            continue
    return None


def path_dns_servers(ip_text=None):
    """DNS-серверы прямого и туннельного путей из ipconfig /all."""
    text = ip_text if ip_text is not None else (run_raw(["ipconfig", "/all"]) or "")
    direct, tunnel = [], []
    for a in parse_ipconfig_adapters(text):
        is_tun = any(pat in (a["name"] + " " + a.get("desc", "")).lower()
                     for pat in VPN_ADAPTER_PATTERNS)
        for d in a.get("dns", []):
            d = d.strip()
            if ":" in d or not _IPISH.match(d):
                continue
            (tunnel if is_tun else direct).append(d)
    return list(dict.fromkeys(direct)), list(dict.fromkeys(tunnel))


def split_dns_check():
    """Корректность split-DNS: разные ли резолверы на прямом и VPN-пути.

    whoami.akamai.net возвращает IP резолвера, который реально сходил в сеть.
    Опрашиваем конкретные DNS-серверы каждого пути напрямую (UDP).
    """
    direct, tunnel = path_dns_servers()
    if not tunnel:
        return {"value": "не настроен (один DNS)", "severity": "neutral"}
    if set(tunnel) == set(direct):
        return {"value": "не настроен (общий DNS)", "severity": "neutral"}
    whoami = "whoami.akamai.net"

    def _resolver_ip(servers):
        for s in servers:
            r = dns_udp_query(s, whoami)
            if isinstance(r, dict) and r.get("ok") and r.get("ips"):
                return r["ips"][0]
        return None

    d_ip = _resolver_ip(direct)
    t_ip = _resolver_ip(tunnel)
    if d_ip and t_ip and d_ip != t_ip:
        dg = get_ip_geo(d_ip) or {}
        tg = get_ip_geo(t_ip) or {}
        dc, tc = dg.get("country", ""), tg.get("country", "")
        if dc and tc:
            dc_ru = dc.lower().startswith("russ")
            tc_ru = tc.lower().startswith("russ")
            ok = dc_ru and not tc_ru
            return {"value": "активен: прямой → %s, VPN → %s" % (dc, tc),
                    "severity": "ok" if ok else "warn"}
        return {"value": "активен (прямой %s, VPN %s)" % (d_ip, t_ip),
                "severity": "ok"}
    if d_ip and t_ip:
        return {"value": "оба пути через один резолвер", "severity": "warn"}
    if d_ip:
        return {"value": "VPN DNS не отвечает", "severity": "bad"}
    if t_ip:
        return {"value": "прямой DNS не отвечает", "severity": "bad"}
    return {"value": "DNS не отвечает", "severity": "bad"}


def get_zone_geo(zone_ips, timeout=8.0):
    """Гео для уникальных IP зон (параллельно, без повторных запросов)."""
    unique = {ip for ip in zone_ips.values() if ip}
    geo_map = {}
    if unique:
        with ThreadPoolExecutor(max_workers=len(unique)) as ex:
            futs = {ex.submit(get_ip_geo, ip, timeout): ip for ip in unique}
            for fut in futs:
                ip = futs[fut]
                try:
                    geo_map[ip] = fut.result()
                except Exception:  # noqa: BLE001
                    geo_map[ip] = None
    return {zone: geo_map.get(ip) for zone, ip in zone_ips.items()}


def get_local_source_ip(host: str, port: int = 443, timeout=4.0):
    """Локальный IP, с которого уходит соединение к host.
    Резолвим через DoH (чисто), чтобы fake-ip/локальный DNS не искажали путь."""
    targets = []
    doh = doh_query(host)
    if doh.get("ok") and doh.get("ips"):
        targets = doh["ips"]
    targets.append(host)  # fallback к системному резолверу
    for t in targets:
        try:
            s = socket.create_connection((t, port), timeout=timeout)
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:  # noqa: BLE001
            continue
    return None


def detect_egress(timeout=4.0):
    """Для каждой зоны определить локальный путь (напрямую/туннель).
    RU-зона определяется по ya.ru (локальный источник), а не по echo."""
    ip_text = run_raw(["ipconfig", "/all"]) or ""
    tunnel_ips = tunnel_interface_ips(parse_ipconfig_adapters(ip_text))
    result = {}
    for zone, host in ZONE_PROBE_HOSTS.items():
        src = get_local_source_ip(host, timeout=timeout)
        if src is None:
            result[zone] = None
        elif src in tunnel_ips:
            result[zone] = {"ip": src, "path": "туннель"}
        else:
            result[zone] = {"ip": src, "path": "напрямую"}
    return result


def system_dns_servers(data):
    """Уникальные DNS-серверы со всех адаптеров (из ipconfig)."""
    ip_text = data.get("Адаптеры", {}).get("text", "") or ""
    servers = []
    for a in parse_ipconfig_adapters(ip_text):
        for dns in a["dns"]:
            d = dns.split("(")[0].strip()
            if d and _IPISH.match(d) and d not in servers:
                servers.append(d)
    return servers


class OnlineRunner(threading.Thread):
    """Фоновый поток, складывает результаты в очередь для GUI."""

    def __init__(self, q):
        super().__init__(daemon=True)
        self.q = q
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        sites = []
        for group, lst in (("RU", RU_SITES), ("Зарубежные", FOREIGN_SITES),
                           ("Заблокированные", BLOCKED_SITES)):
            for name, url in lst:
                sites.append((group, name, url))

        def _site(item):
            g, name, url = item
            # заблокированные часто висят до таймаута — режем короче
            to = 2.0 if g == "Заблокированные" else 5.0
            return g, run_site_test(name, url, timeout=to)

        # 3-4 параллельных запроса: не триггерим VPN/DNS/CDN всплеском
        ex = ThreadPoolExecutor(max_workers=4)
        try:
            futs = {ex.submit(_site, s): s for s in sites}
            for fut in as_completed(futs):
                if self._stop.is_set():
                    break
                g, res = fut.result()
                self.q.put(("site", g, res))
        finally:
            ex.shutdown(wait=False, cancel_futures=True)

        if not self._stop.is_set():
            def _dns(item):
                label, server = item
                return label, run_dns_server_test(server)

            ex2 = ThreadPoolExecutor(max_workers=3)
            try:
                futs = {ex2.submit(_dns, d): d for d in DNS_SERVERS}
                for fut in as_completed(futs):
                    if self._stop.is_set():
                        break
                    label, r = fut.result()
                    self.q.put(("dns", label, r))
            finally:
                ex2.shutdown(wait=False, cancel_futures=True)

        if not self._stop.is_set():
            gw = default_gateway()
            if gw:
                self.q.put(("gateway", gw, ping_test(gw)))

        # Внешний IP + скорость + UDP-качество по зонам (параллельно)
        if not self._stop.is_set():
            tasks = [("speed", z, SPEED_ENDPOINTS[z])
                     for z in ("RU", "Зарубежные", "Заблокированные")]
            tasks.append(("ip", None, None))
            tasks += [("udp", z, None) for z in UDP_TARGETS]

            def _extra(item):
                kind, zone, url = item
                if kind == "ip":
                    zone_ips = get_zone_ips()
                    zone_geo = get_zone_geo(zone_ips)
                    egress = detect_egress()
                    payload = {z: {"ip": zone_ips.get(z),
                                   "geo": zone_geo.get(z),
                                   "egress": egress.get(z)} for z in ZONES}
                    return ("ip", None, payload)
                if kind == "udp":
                    return ("udp", zone, udp_zone_test(zone))
                return ("speed", zone, speed_test(url))

            ex3 = ThreadPoolExecutor(max_workers=4)
            try:
                futs = [ex3.submit(_extra, t) for t in tasks]
                for fut in as_completed(futs):
                    if self._stop.is_set():
                        break
                    kind, a, b = fut.result()
                    self.q.put((kind, a, b))
            finally:
                ex3.shutdown(wait=False, cancel_futures=True)

        self.q.put(("done", None, None))


def default_gateway():
    """Физический шлюз по умолчанию (без туннельных On-link)."""
    txt = run_raw(["route", "print", "-4"]) or ""
    defaults = [r for r in parse_route_print(txt)
                if r["network"] == "0.0.0.0" and r["mask"] == "0.0.0.0"
                and r["gateway"].lower() not in ("on-link", "связанный")]
    if defaults:
        defaults.sort(key=lambda r: r["metric"])
        return defaults[0]["gateway"]
    routes = ps_json(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric "
        "| Select-Object -First 1 NextHop | ConvertTo-Json -Compress")
    if isinstance(routes, dict):
        return routes.get("NextHop")
    if isinstance(routes, list) and routes:
        return routes[0].get("NextHop")
    return None


# ----------------------------------------------------------------------------
# Экспорт
# ----------------------------------------------------------------------------

def export_report(path, data, findings, online=None):
    payload = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "admin": is_admin(),
        "findings": [{"severity": s, "message": m} for s, m in findings],
        "sections": data,
        "online": online if online is not None else {},
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def render_text(data, findings, online=None):
    lines = []
    lines.append("=" * 70)
    lines.append("NetUtil — отчёт о сетевой конфигурации Windows")
    lines.append("Сгенерировано: " + time.strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Запуск от администратора: " + ("да" if is_admin() else "нет"))
    lines.append("=" * 70)

    if findings:
        lines.append("\nНАХОДКИ:")
        for sev, msg in findings:
            lines.append(f"  [{sev.upper()}] {msg}")
    else:
        lines.append("\nНАХОДКИ: явных проблем не обнаружено")

    for title, _fn in SECTIONS:
        sec = data.get(title, {})
        lines.append("\n" + "=" * 70)
        lines.append("## " + title)
        lines.append("=" * 70)
        for t in sec.get("tables", []):
            cols = t.get("columns", [])
            lines.append("\n-- " + t.get("name", ""))
            lines.append(" | ".join(cols))
            for row in t.get("rows", []):
                lines.append(" | ".join(str(c) for c in row))
        if sec.get("text"):
            lines.append("\n" + sec["text"])

    if online:
        lines.append("\n" + "=" * 70)
        lines.append("## Онлайн-проверка")
        lines.append("=" * 70)
        lines.append(json.dumps(online, ensure_ascii=False, indent=2))
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------

class NetUtilApp:
    def __init__(self, root):
        self.root = root
        root.title("NetUtil — диагностика сети Windows 11")
        root.geometry("1120x760")

        self.data = {}
        self.findings = []
        self.online_rows = {}   # (kind, key) -> row id
        self.queue = _queue.Queue()
        self.runner = None
        self.online_data = {}
        self.zone_state = {}
        self.zone_widgets = {}
        self.status_items = {}
        self._init_zone_state()

        self._build_ui()
        self.refresh_all()

    def _init_zone_state(self):
        self.zone_state = {}
        for z in ZONES:
            self.zone_state[z] = {"total": len(ZONE_SITES[z]), "ok": 0,
                                  "lats": [], "speed": None, "speed_ok": False}

    # ----- построение интерфейса -----
    def _build_ui(self):
        top = tk.Frame(self.root)
        top.pack(fill="x", padx=8, pady=6)

        self.btn_refresh = tk.Button(top, text="Обновить конфигурацию",
                                     command=self.refresh_all)
        self.btn_refresh.pack(side="left")

        self.btn_online = tk.Button(top, text="▶ Запустить онлайн-проверку",
                                    command=self.start_online, bg="#dff0d8")
        self.btn_online.pack(side="left", padx=8)

        self.auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="Автообновление онлайн (каждые 60 с)",
                       variable=self.auto_var, command=self._toggle_auto).pack(side="left")

        self.status = tk.StringVar(value="Готово")
        tk.Label(top, textvariable=self.status, fg="#555").pack(side="right")

        self.btn_export = tk.Button(top, text="Сохранить отчёт…",
                                    command=self.export)
        self.btn_export.pack(side="right", padx=4)

        admin = "Запущено от АДМИНИСТРАТОРА" if is_admin() else \
                "⚠ Без прав администратора (часть данных недоступна)"
        tk.Label(self.root, text=admin,
                 fg="#a00" if not is_admin() else "#0a0").pack(anchor="w", padx=10)

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=6)

        # Вкладка «Главная» (dashboard) — первая
        self._build_dashboard()

        # Вкладка «Сводка»
        self.summary_frame = tk.Frame(self.nb)
        self.nb.add(self.summary_frame, text="Сводка")
        self.findings_text = self._add_text(self.summary_frame)

        # Вкладка «Онлайн»
        self.online_frame = tk.Frame(self.nb)
        self.nb.add(self.online_frame, text="Онлайн-проверка")
        self.online_tree, self.online_columns = self._add_tree(
            self.online_frame,
            ["Проверка", "Цель", "DNS", "TCP 443", "HTTP (прокси)", "HTTP (напрямую)"],
        )

        # Остальные секции
        self.section_widgets = {}
        for title, _fn in SECTIONS:
            frame = tk.Frame(self.nb)
            self.nb.add(frame, text=title)
            self.section_widgets[title] = frame

    def _build_dashboard(self):
        frame = tk.Frame(self.nb)
        self.nb.add(frame, text="Главная")

        self.ip_var = tk.StringVar(value="Внешний IP: …")
        tk.Label(frame, textvariable=self.ip_var,
                 font=("Segoe UI", 12, "bold")).pack(anchor="w", padx=12,
                                                     pady=(12, 0))
        self.dns_var = tk.StringVar(value="DNS-серверы системы: …")
        tk.Label(frame, textvariable=self.dns_var, fg="#555").pack(anchor="w",
                                                                   padx=12)

        # Панель «Состояние системы» (короткие вердикты)
        panel = tk.Frame(frame, relief="ridge", bd=1, padx=8, pady=6)
        panel.pack(fill="x", padx=12, pady=(8, 0))
        tk.Label(panel, text="Состояние системы", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.status_frame = tk.Frame(panel)
        self.status_frame.pack(fill="x", pady=(4, 0))

        row = tk.Frame(frame)
        row.pack(fill="x", padx=12, pady=12)
        for z in ZONES:
            zf = tk.Frame(row, relief="ridge", bd=2, padx=10, pady=10)
            zf.pack(side="left", fill="both", expand=True, padx=4)
            tk.Label(zf, text=z, font=("Segoe UI", 11, "bold")).pack()
            ip_lbl = tk.Label(zf, text="IP: …", fg="#357")
            ip_lbl.pack(anchor="w")
            status = tk.Label(zf, text="…", font=("Segoe UI", 14, "bold"),
                              width=14)
            status.pack(pady=6)
            ping = tk.Label(zf, text="Пинг: —", fg="#555")
            ping.pack(anchor="w")
            speed = tk.Label(zf, text="Скорость: …", fg="#555")
            speed.pack(anchor="w")
            sites = tk.Label(zf, text="Сайтов: 0/%d" % len(ZONE_SITES[z]),
                             fg="#555")
            sites.pack(anchor="w")
            self.zone_widgets[z] = {"status": status, "ping": ping,
                                    "speed": speed, "sites": sites,
                                    "ip": ip_lbl}

        tk.Label(frame, text="Доступно = все сайты зоны отвечают; "
                             "частично = отвечает часть; недоступно = ни один. "
                             "Скорость — загрузка фрагмента файла.",
                 fg="#888").pack(anchor="w", padx=12)

    def _update_zone(self, zone):
        w = self.zone_widgets.get(zone)
        if not w:
            return
        st = self.zone_state.get(zone)
        if not st:
            return
        total, ok = st["total"], st["ok"]
        status, sev = zone_status(ok, total)
        color = {"ok": "#d9f2d9", "warn": "#f7eec9", "bad": "#f2d9d9",
                 "neutral": "#eee"}.get(sev, "#eee")
        w["status"].configure(text=status, bg=color)
        if st["lats"]:
            best = min(st["lats"])
            w["ping"].configure(text="Пинг: %d мс (мин)" % best)
        else:
            w["ping"].configure(text="Пинг: —")
        if st.get("speed_ok"):
            w["speed"].configure(text="Скорость: %s Мбит/с" % st["speed"])
        elif st.get("speed") is not None:
            w["speed"].configure(text="Скорость: нет")
        else:
            w["speed"].configure(text="Скорость: …")
        w["sites"].configure(text="Сайтов: %d/%d" % (ok, total))

    def _update_dashboard_dns(self):
        servers = system_dns_servers(self.data)
        self.dns_var.set("DNS-серверы системы: " +
                         (", ".join(servers) if servers else "не найдены"))

    def _populate_status(self):
        self.status_items = {}
        for item in determine_status(self.data):
            self.status_items[item["id"]] = item
        self.status_items["dns_live"] = {"id": "dns_live",
                                         "label": "DNS (напрямую)",
                                         "value": "проверяется…",
                                         "severity": "neutral"}
        self.status_items["vpn_quality"] = {"id": "vpn_quality",
                                            "label": "VPN-качество",
                                            "value": "проверяется…",
                                            "severity": "neutral"}
        self.status_items["split"] = {"id": "split",
                                      "label": "Split-tunneling",
                                      "value": "проверяется…",
                                      "severity": "neutral"}
        self.status_items["resolver"] = {"id": "resolver",
                                         "label": "DNS-резолвер",
                                         "value": "проверяется…",
                                         "severity": "neutral"}
        self.status_items["censorship"] = {"id": "censorship",
                                           "label": "DNS-фильтрация",
                                           "value": "проверяется…",
                                           "severity": "neutral"}
        self._render_status()

    def _set_status(self, sid, label, value, severity):
        self.status_items[sid] = {"id": sid, "label": label,
                                  "value": value, "severity": severity}
        self._render_status()

    def _render_status(self):
        colors = {"ok": "#d9f2d9", "warn": "#f7eec9", "bad": "#f2d9d9",
                  "neutral": "#e8e8e8"}
        for child in self.status_frame.winfo_children():
            child.destroy()
        for sid in ("vpn", "route", "split", "vpn_quality", "proxy",
                    "dns_live", "resolver", "censorship", "cache", "winsock",
                    "adapters"):
            item = self.status_items.get(sid)
            if not item:
                continue
            row = tk.Frame(self.status_frame)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=item["label"] + ":", anchor="w",
                     width=22).pack(side="left")
            tk.Label(row, text=item["value"], anchor="w",
                     bg=colors.get(item["severity"], "#eee")).pack(
                         side="left", fill="x", expand=True, padx=(4, 0))

    def _start_dns_check(self):
        self._dns_result = None

        def worker():
            self._dns_result = dns_analysis()
        threading.Thread(target=worker, daemon=True).start()
        self._poll_dns()

    def _poll_dns(self):
        res = self._dns_result
        if res is not None:
            # 1) корректность прямого резолвинга
            d = res.get("direct", {})
            sev = "ok" if d.get("state") == "ok" else "bad"
            self._set_status("dns_live", "DNS (напрямую)", d.get("value", "?"), sev)
            # 2) резолвер + страна
            g = res.get("resolver_geo")
            if g and g.get("country"):
                prov = (g.get("org") or "").split(" ")[0]
                self._set_status("resolver", "DNS-резолвер",
                                 "%s · %s" % (g["country"], prov), "ok")
            elif res.get("whoami"):
                self._set_status("resolver", "DNS-резолвер",
                                 "определён (без гео)", "neutral")
            else:
                self._set_status("resolver", "DNS-резолвер",
                                 "не определён", "neutral")
            # 3) цензура/фильтрация
            c = res.get("censorship", {})
            csev = "ok" if c.get("state") == "clean" else "bad"
            self._set_status("censorship", "DNS-фильтрация",
                             c.get("value", "?"), csev)
            return
        try:
            self.root.after(300, self._poll_dns)
        except Exception:  # noqa: BLE001  (окно закрыто)
            pass

    def _update_vpn_quality(self):
        vpn_item = self.status_items.get("vpn")
        vpn_active = (vpn_item and vpn_item.get("value") == "Активен")
        if not vpn_active:
            self._set_status("vpn_quality", "VPN-качество", "VPN выключен",
                             "neutral")
            return
        value, sev = vpn_quality_verdict(self.zone_state)
        self._set_status("vpn_quality", "VPN-качество", value, sev)

    def _start_vpn_check(self):
        self._speed_result = None

        def worker():
            self._speed_result = speed_test(SPEED_ENDPOINTS["Зарубежные"])
        threading.Thread(target=worker, daemon=True).start()
        self._poll_vpn()

    def _poll_vpn(self):
        res = self._speed_result
        if res is not None:
            st = self.zone_state.get("Зарубежные", {})
            if res.get("ok"):
                st["speed"] = res.get("mbps")
                st["speed_ok"] = True
            else:
                st["speed"] = res.get("error", "?")
                st["speed_ok"] = False
            self._update_zone("Зарубежные")
            self._update_vpn_quality()
            return
        try:
            self.root.after(300, self._poll_vpn)
        except Exception:  # noqa: BLE001  (окно закрыто)
            pass

    def _format_geo(self, geo, with_asn=True):
        if not geo:
            return ""
        parts = []
        if geo.get("country"):
            parts.append(str(geo["country"]))
        if geo.get("city"):
            parts.append(str(geo["city"]))
        if with_asn and geo.get("asn"):
            parts.append(str(geo["asn"]))
        return ", ".join(parts)

    def _render_ip(self, info):
        for z in ZONES:
            w = self.zone_widgets.get(z)
            if not w:
                continue
            d = info.get(z) or {}
            ip = d.get("ip")
            geo = self._format_geo(d.get("geo"), with_asn=False)
            if ip and geo:
                w["ip"].configure(text=f"IP: {ip} ({geo})")
            elif ip:
                w["ip"].configure(text="IP: " + ip)
            else:
                w["ip"].configure(text="IP: не определён")

        ru = (info.get("RU") or {}).get("ip")
        foreign = (info.get("Зарубежные") or {}).get("ip")
        ru_geo = self._format_geo((info.get("RU") or {}).get("geo"))
        foreign_geo = self._format_geo((info.get("Зарубежные") or {}).get("geo"))
        if ru and foreign and ru != foreign:
            self.ip_var.set(f"Split-роутинг: RU -> {ru} ({ru_geo}) | "
                            f"зарубежный -> {foreign} ({foreign_geo})")
        elif foreign:
            self.ip_var.set("Внешний IP: " + foreign +
                            (f" ({foreign_geo})" if foreign_geo else ""))
        elif ru:
            self.ip_var.set("Внешний IP: " + ru +
                            (f" ({ru_geo})" if ru_geo else ""))
        else:
            self.ip_var.set("Внешний IP: не определён")

        # split-tunneling — по внешнему IP (echo), egress как запасной
        zone_ips = {z: (info.get(z) or {}).get("ip") for z in ZONES}
        egress = {z: (info.get(z) or {}).get("egress") for z in ZONES}
        vpn_item = self.status_items.get("vpn")
        vpn_active = bool(vpn_item and vpn_item.get("value") == "Активен")
        val, sev = split_tunneling_status(zone_ips, vpn_active, egress)
        self._set_status("split", "Split-tunneling", val, sev)

    def _render_speed(self, zone, res):
        st = self.zone_state.get(zone)
        if not st:
            return
        if res.get("ok"):
            st["speed"] = res.get("mbps")
            st["speed_ok"] = True
        else:
            st["speed"] = res.get("error", "?")
            st["speed_ok"] = False
        self._update_zone(zone)
        self._update_vpn_quality()

    def _add_text(self, parent):
        txt = tk.Text(parent, wrap="word", font=("Consolas", 10))
        sb = tk.Scrollbar(parent, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)
        return txt

    def _add_tree(self, parent, columns):
        cols = [f"c{i}" for i in range(len(columns))]
        tree = ttk.Treeview(parent, columns=cols, show="headings")
        for col, name in zip(cols, columns):
            tree.heading(col, text=name)
            tree.column(col, width=170, anchor="w")
        vsb = tk.Scrollbar(parent, orient="vertical", command=tree.yview)
        hsb = tk.Scrollbar(parent, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        tree.tag_configure("ok", background="#d9f2d9")
        tree.tag_configure("fail", background="#f2d9d9")
        tree.tag_configure("warn", background="#f7eec9")
        return tree, columns

    # ----- сбор данных -----
    def refresh_all(self):
        self.status.set("Сбор конфигурации…")
        self.root.update_idletasks()
        data, findings = collect_all()
        self.data = data
        self.findings = findings
        self._render_findings()
        self._render_sections()
        self._update_dashboard_dns()
        self._populate_status()
        self._start_dns_check()
        self._start_vpn_check()
        self.status.set("Конфигурация собрана: " +
                        time.strftime("%H:%M:%S"))

    def _render_findings(self):
        t = self.findings_text
        t.delete("1.0", "end")
        if not self.findings:
            t.insert("end", "Явных проблем не обнаружено.\n")
            return
        color = {"error": "#c00", "warn": "#a80", "info": "#08c"}
        for sev, msg in self.findings:
            t.insert("end", f"[{sev.upper()}] ", (sev,))
            t.insert("end", msg + "\n")
            t.tag_configure(sev, foreground=color.get(sev, "#000"))
        t.insert("end", "\nПодсказки по частым причинам:\n", ("h",))
        t.tag_configure("h", foreground="#333", font=("Consolas", 10, "bold"))
        t.insert("end",
            "• Несколько шлюзов/метрик: netsh int ip reset, проверь метрики адаптеров.\n"
            "• Сломанный Winsock: netsh winsock reset && netsh int ip reset (и перезагрузка).\n"
            "• Мусорные TUN/TAP: удали адаптеры в диспетчере устройств или из настроек VPN-клиента.\n"
            "• Остаточный прокси: отключи в Параметры -> Сеть -> Прокси.\n"
            "• DNS: ipconfig /flushdns, проверь NRPT и DoH.\n"
            "• MTU: при обрывах попробуй 1400–1420 на туннельном адаптере.\n"
            "• SSL-ошибка на RU-сайтах = требование сертификатов Минцифры "
            "(национальный TLS); такие сайты считаются доступными.\n")

    def _render_sections(self):
        for title, _fn in SECTIONS:
            frame = self.section_widgets[title]
            for child in frame.winfo_children():
                child.destroy()
            sec = self.data.get(title, {})
            tables = sec.get("tables", [])
            text = sec.get("text", "")
            if tables:
                self._render_tables(frame, tables)
            if text:
                lbl = tk.Label(frame, text="Текстовый вывод:", anchor="w",
                               fg="#666")
                lbl.pack(fill="x", padx=4, pady=(4, 0))
                txt = self._add_text(frame)
                txt.insert("1.0", text)
                txt.configure(state="disabled")

    def _render_tables(self, parent, tables):
        for t in tables:
            cols = t.get("columns", [])
            rows = t.get("rows", [])
            name = t.get("name", "")
            if name:
                tk.Label(parent, text=name, anchor="w",
                         font=("Segoe UI", 10, "bold")).pack(fill="x", padx=4,
                                                              pady=(6, 0))
            ids = [f"c{i}" for i in range(len(cols))]
            tree = ttk.Treeview(parent, columns=ids, show="headings", height=8)
            for col, cname in zip(ids, cols):
                tree.heading(col, text=cname)
                tree.column(col, width=180, anchor="w")
            vsb = tk.Scrollbar(parent, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=vsb.set)
            vsb.pack(side="right", fill="y")
            tree.pack(fill="both", expand=True, padx=4)
            for row in rows:
                tree.insert("", "end", values=tuple(str(c) for c in row))

    # ----- онлайн-проверка -----
    def start_online(self):
        if self.runner and self.runner.is_alive():
            return
        for item in self.online_tree.get_children():
            self.online_tree.delete(item)
        self.online_rows.clear()
        self.online_data = {}
        self._init_zone_state()
        for z in ZONES:
            self._update_zone(z)
            w = self.zone_widgets.get(z)
            if w:
                w["ip"].configure(text="IP: …")
        self.ip_var.set("Внешний IP: …")
        self._set_status("vpn_quality", "VPN-качество", "проверяется…", "neutral")
        self._set_status("split", "Split-tunneling", "проверяется…", "neutral")
        self.btn_online.configure(text="⏳ Проверка…", state="disabled")
        self.status.set("Онлайн-проверка запущена…")
        self.runner = OnlineRunner(self.queue)
        self.runner.start()
        self._poll_queue()

    def _poll_queue(self):
        try:
            while True:
                kind, key, res = self.queue.get_nowait()
                if kind == "site":
                    self._render_site(key, res)
                elif kind == "dns":
                    self._render_dns(key, res)
                elif kind == "gateway":
                    self._render_gateway(key, res)
                elif kind == "speed":
                    self._render_speed(key, res)
                elif kind == "ip":
                    self._render_ip(res)
                elif kind == "done":
                    self.btn_online.configure(text="▶ Запустить онлайн-проверку",
                                              state="normal")
                    self.status.set("Онлайн-проверка завершена: " +
                                    time.strftime("%H:%M:%S"))
                    self._schedule_auto()
                    return
        except _queue.Empty:
            pass
        self.root.after(150, self._poll_queue)

    def _status_cell(self, d, ok_val="ok"):
        if not d.get("ok"):
            return "✗ " + (d.get("error", "?"))[:40], "fail"
        return ok_val, "ok"

    def _render_site(self, group, res):
        dns = res.get("dns", {})
        dns_cell = (", ".join(dns.get("ips", []))[:30]
                    if dns.get("ok") else "✗ " + dns.get("error", "")[:25])

        tcp = res.get("tcp", {})
        tcp_cell = (f"ok {tcp.get('rtt_ms')}мс" if tcp.get("ok")
                    else "✗ " + tcp.get("error", "")[:25])

        http = res.get("http", {})
        if http.get("ok"):
            if http.get("http_error"):
                http_cell = f"{http.get('status')} · {http.get('rtt_ms')}мс (дошло)"
            else:
                http_cell = f"{http.get('status')} · {http.get('rtt_ms')}мс"
        elif http.get("ssl_error"):
            http_cell = "SSL серт (Минцифры?)"
        else:
            http_cell = "✗ " + http.get("error", "")[:25]

        http_d = res.get("http_direct", {})
        if http_d.get("ok"):
            if http_d.get("http_error"):
                http_d_cell = f"{http_d.get('status')} · {http_d.get('rtt_ms')}мс (дошло)"
            else:
                http_d_cell = f"{http_d.get('status')} · {http_d.get('rtt_ms')}мс"
        elif http_d.get("ssl_error"):
            http_d_cell = "SSL серт (Минцифры?)"
        else:
            http_d_cell = "✗ " + http_d.get("error", "")[:25]

        label = f"[{group}] {res.get('name')}"
        iid = self.online_tree.insert(
            "", "end", values=(label, res.get("host"), dns_cell, tcp_cell,
                               http_cell, http_d_cell))
        reachable = site_reachable(res, group)
        self.online_tree.item(iid, tags=("ok" if reachable else "fail",))
        self.online_rows[("site", group + res.get("name"))] = iid
        self.online_data.setdefault("sites", {})[group + " " + res.get("name")] = {
            "host": res.get("host"), "dns": dns, "tcp": tcp,
            "http": http, "http_direct": http_d,
        }

        # агрегат по зоне для главного экрана
        st = self.zone_state.get(group)
        if st:
            if reachable:
                st["ok"] += 1
                rtt = tcp.get("rtt_ms")  # честный TCP-пинг (RTT)
                if rtt:
                    st["lats"].append(rtt)
            self._update_zone(group)

    def _render_dns(self, label, res):
        cell = ""
        tag = "ok"
        if res.get("ok"):
            ips = ", ".join(res.get("ips", []))[:24]
            cell = f"ok {res.get('rtt_ms')}мс {ips}"
        else:
            cell = "✗ " + res.get("error", "")[:30]
            tag = "fail"
        iid = self.online_tree.insert(
            "", "end", values=(f"[DNS] {label}", res.get("server", ""),
                               cell, "", "", ""), tags=(tag,))
        self.online_rows[("dns", label)] = iid
        self.online_data.setdefault("dns", {})[label] = res

    def _render_gateway(self, gw, res):
        cell = (f"ok {res.get('rtt_ms')}мс" if res.get("ok")
                else "✗ " + res.get("error", ""))
        tag = "ok" if res.get("ok") else "fail"
        iid = self.online_tree.insert(
            "", "end", values=("[Шлюз]", gw, cell, "", "", ""), tags=(tag,))
        self.online_rows[("gateway", gw)] = iid
        self.online_data["gateway"] = {"gw": gw, "ping": res}

    def _schedule_auto(self):
        if self.auto_var.get():
            self.root.after(60000, self.start_online)

    def _toggle_auto(self):
        if not self.auto_var.get() and self.runner:
            self.runner.stop()

    # ----- экспорт -----
    def export(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="netutil-report.json",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")])
        if not path:
            return
        export_report(path, self.data, self.findings, self.online_data)
        self.status.set("Отчёт сохранён: " + path)


# ----------------------------------------------------------------------------
# Точка входа
# ----------------------------------------------------------------------------

def main():
    if "--cli" in sys.argv or "--export" in sys.argv:
        # Безопасный вывод в консоль с любой кодировкой (cp866/cp1251/utf-8)
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(errors="replace")
            except Exception:  # noqa: BLE001
                pass
        data, findings = collect_all()
        online = None
        print(render_text(data, findings, online))
        for arg in sys.argv[1:]:
            if arg.startswith("--export"):
                parts = arg.split("=", 1)
                path = parts[1] if len(parts) == 2 else "netutil-report.json"
                export_report(path, data, findings)
                print(f"\nОтчёт сохранён: {path}")
        return

    if tk is None:
        sys.stderr.write("Tkinter недоступен — GUI не запустится.\n")
        sys.stderr.write("Используй: python netutil.py --cli\n")
        return
    root = tk.Tk()
    NetUtilApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
