#pragma once

#include <array>
#include <span>

#include <AUI/Common/AOptional.h>
#include <AUI/Common/ASet.h>
#include <AUI/Common/AString.h>
#include <AUI/Common/AVector.h>

namespace net {

/// Name markers of leftovers of VPN tools (Amnezia, sing-box, xray, Hiddify...).
inline constexpr auto VPN_PROCESS_PATTERNS = std::to_array<AStringView>({
    "xray",      "sing-box", "singbox", "hysteria",    "hiddify", "amnezia",  "clash",       "v2ray",    "tun2socks",
    "happ",      "nekoray",  "nekobox", "mihomo",      "wireguard", "openvpn", "shadowsocks", "ss-local", "ssr",
    "trojan",    "warp-svc", "cloudflared", "tailscale", "zerotier", "outline", "psiphon",     "sstap",    "naiveproxy",
});

inline constexpr auto VPN_SERVICE_EXTRA_PATTERNS = std::to_array<AStringView>({
    "wg-quick", "nordvpn", "protonvpn", "cloudflarewarp",
});

inline constexpr auto VPN_ADAPTER_PATTERNS = std::to_array<AStringView>({
    "tap",      "tun",      "wintun",  "amnezia", "sing-box", "singbox",  "hiddify", "xray",
    "wireguard", "openvpn", "utun",    "hysteria", "warp",    "tailscale", "zerotier", "outline",
    "psiphon",  "nordlynx", "metavpn", "vpngate", "wiresock", "tun2socks", "clash",   "mihomo",
});

inline constexpr auto VM_ADAPTER_PATTERNS = std::to_array<AStringView>({ "vmware", "virtualbox", "hyper-v", "vnet" });

struct Adapter {
    AString name;
    AString rawName;
    bool unknown = false;
    AString desc;
    AString ipv4;
    AString gateway;
    AVector<AString> dns;
    AString status;
    AString dhcp;

    bool operator==(const Adapter&) const = default;
};

struct Route {
    AString network;
    AString mask;
    AString gateway;
    /// IP of the outgoing interface, as `route print` shows it.
    AString iface;
    int metric = 0;

    bool operator==(const Route&) const = default;
};

struct CacheRecord {
    AString name;
    AVector<AString> ips;

    bool operator==(const CacheRecord&) const = default;
};

struct WinsockProvider {
    AString type;
    AString desc;
    AString path;

    bool operator==(const WinsockProvider&) const = default;
};

AVector<Route> parseRoutePrint(AStringView text);
AVector<Adapter> parseIpconfigAdapters(AStringView text);
AVector<CacheRecord> parseDisplayDns(AStringView text);
AVector<WinsockProvider> parseWinsockCatalog(AStringView text);

/// Looks like an IP address (digits, hex, dots, colons, zone id).
bool isIpish(AStringView s);
AOptional<uint32_t> parseIpv4(AStringView ip);

/// CGNAT / benchmark / APIPA ranges typical for tunnels.
bool isTunnelIp(AStringView ip);

/// 255.0.0.0 -> 8, 128.0.0.0 -> 1.
AOptional<int> maskToPrefix(AStringView mask);

/// Loopback, private or 0.0.0.0 in a DNS answer: a sign of spoofing.
bool isSuspiciousCacheIp(AStringView ip);

bool isTunnelAdapter(const Adapter& adapter);
bool isVmAdapter(const Adapter& adapter);

/// IPv4 addresses of tunnel adapters; routes are matched to tunnels by them.
ASet<AString> tunnelInterfaceIps(std::span<const Adapter> adapters);

bool routeThroughTunnel(const Route& route, const ASet<AString>& tunnelIps);

bool isDefaultRoute(const Route& route);

/// "On-link" in the gateway column.
bool isOnLink(const Route& route);

struct TunnelCapture {
    /// Share of the IPv4 space routed into tunnels, counting /1../8 capture routes (Amnezia and others).
    double fraction = 0;
    AVector<Route> routes;
};

TunnelCapture tunnelTrafficFraction(std::span<const Route> routes, const ASet<AString>& tunnelIps);

/// Default routes sorted by metric.
AVector<Route> defaultRoutes(std::span<const Route> routes);

}   // namespace net
