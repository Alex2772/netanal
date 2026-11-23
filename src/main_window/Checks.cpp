#include "MainWindow.h"

#include <AUI/Thread/AThreadPool.h>

#include <algorithm>

#include "Match.h"
#include "main_window/Common.h"
#include "Report.h"
#include "Shell.h"

using namespace ass;
using namespace declarative;
using namespace net;
using namespace main_window;

namespace {

/// DNS items stay silent in the summary while they are fine.
constexpr bool isDnsItem(Sid id) {
    return id == Sid::DNS_LIVE || id == Sid::RESOLVER || id == Sid::SPLIT_DNS || id == Sid::CENSORSHIP ||
           id == Sid::CACHE;
}

const Verdict CHECKING = { .value = "проверяется…" };

AString cut(const AString& s, size_t n) { return s.length() <= n ? s : AString(s.substr(0, n)); }

AString ms1(Ms ms) { return "{:.1f}"_format(ms.count()); }

AString failCell(const AString& error, size_t n) { return "× " + cut(error, n); }

Cell httpCell(const HttpResult& r) {
    return match(
        r,
        [](const HttpAnswered& a) {
            return Cell { .value = "{} · {}мс"_format(a.status, ms1(a.rtt)), .color = theme::textColor(Severity::OK) };
        },
        [](const HttpFailed& f) {
            if (f.sslError) {
                return Cell { .value = "SSL серт (Минцифры?)", .color = theme::textColor(Severity::WARN) };
            }
            return Cell { .value = failCell(f.error, 22), .color = theme::textColor(Severity::BAD) };
        });
}

struct Collected {
    SystemSnapshot snapshot;
    AVector<Finding> findings;
};

}   // namespace

// ---- status ----------------------------------------------------------------------------------------------------

Verdict MainWindow::status(Sid id) const { return mStatus[size_t(id)]->valueOr(PENDING); }

void MainWindow::setStatus(Sid id, Verdict verdict) { mStatus[size_t(id)] = std::move(verdict); }

AVector<SummaryItem> MainWindow::summaryItems() const {
    AVector<SummaryItem> items;
    // zones are judged after the online check
    if (!*mChecking && mOnlineDone) {
        for (auto zone : ZONES) {
            const auto& z = *mZones[zone]->stats;
            items << SummaryItem {
                .label = "Зона {}"_format(zoneName(zone)),
                .value = "{}/{}"_format(z.ok, z.total),
                .severity = zoneStatus(z.ok, z.total).severity
            };
        }
    }
    for (const auto& s : STATUS_SPECS) {
        const auto& item = *mStatus[size_t(s.id)];
        if (!item || item->severity == Severity::NEUTRAL) {
            continue;
        }
        if (s.id == Sid::VPN_QUALITY && item->value == "VPN выключен") {
            continue;   // not a problem, the VPN is just off
        }
        if ((isDnsItem(s.id) || s.id == Sid::WINSOCK) && item->severity == Severity::OK) {
            continue;
        }
        items << SummaryItem { .label = AString(s.label), .value = item->value, .severity = item->severity };
    }
    // problems first, then warnings, then OK
    auto order = [](Severity s) { return s == Severity::BAD ? 0 : s == Severity::WARN ? 1 : 2; };
    std::ranges::stable_sort(items, [&](const SummaryItem& a, const SummaryItem& b) {
        return order(a.severity) < order(b.severity);
    });
    return items;
}

SummaryState MainWindow::summaryState() const {
    // no negative verdict until the check finishes, so the status does not jump
    if (*mChecking || !mOnlineDone) {
        return SummaryState::PENDING;
    }
    const auto items = summaryItems();
    const auto has = [&](Severity s) {
        return std::ranges::any_of(items, [&](const SummaryItem& i) { return i.severity == s; });
    };
    if (has(Severity::BAD)) {
        return SummaryState::BAD;
    }
    if (has(Severity::WARN)) {
        return SummaryState::WARN;
    }
    return SummaryState::OK;
}

void MainWindow::populateStatus() {
    const auto s = determineStatus(*mSnapshot);
    mVpnActive = s.vpnActive;
    setStatus(Sid::VPN, s.vpn);
    setStatus(Sid::ROUTE, s.route);
    setStatus(Sid::PROXY, s.proxy);
    setStatus(Sid::CACHE, s.cache);
    setStatus(Sid::WINSOCK, s.winsock);
    setStatus(Sid::ADAPTERS, s.adapters);
    for (auto id : { Sid::DNS_LIVE, Sid::RESOLVER, Sid::SPLIT_DNS, Sid::CENSORSHIP, Sid::VPN_QUALITY, Sid::SPLIT,
                     Sid::DIAGNOSIS }) {
        setStatus(id, CHECKING);
    }
}

void MainWindow::updateVpnQuality() {
    if (!mVpnActive) {
        setStatus(Sid::VPN_QUALITY, { .value = "VPN выключен", .severity = Severity::NEUTRAL });
        return;
    }
    setStatus(Sid::VPN_QUALITY, vpnQualityVerdict(*mZones[Zone::FOREIGN]->stats));
}

// ---- refresh ---------------------------------------------------------------------------------------------------

AFuture<> MainWindow::refreshAll() {
    if (mCollecting) {
        co_return;
    }
    mCollecting = true;
    mStatusText = "Проверка (конфигурация + онлайн)…";
    auto collected = co_await (AUI_THREADPOOL {
        auto snapshot = collectSystem();
        auto findings = analyze(snapshot);
        return Collected { .snapshot = std::move(snapshot), .findings = std::move(findings) };
    });
    mCollecting = false;
    mSnapshot = std::move(collected.snapshot);
    mFindings = std::move(collected.findings);
    populateStatus();
    mTasks << checkDns();
    mTasks << checkSplitDns();
    mTasks << checkOnline();
}

AFuture<> MainWindow::checkDns() {
    const auto report = co_await (AUI_THREADPOOL { return dnsAnalysis(); });
    setStatus(Sid::DNS_LIVE, report.direct);
    setStatus(Sid::RESOLVER, resolverVerdict(report));
    setStatus(Sid::CENSORSHIP, report.censorship);
    mResolverCountry = geoCountry(report.resolverGeo);
}

AFuture<> MainWindow::checkSplitDns() {
    const auto network = mSnapshot->network;
    setStatus(Sid::SPLIT_DNS, co_await (AUI_THREADPOOL { return splitDnsCheck(network); }));
}

// ---- zones -----------------------------------------------------------------------------------------------------

void MainWindow::resetZones() {
    mCells = {};
    for (auto zone : ZONES) {
        mZones[zone]->stats = ZoneStats { .total = mSites[zone].size() };
        mZones[zone]->ip = std::nullopt;
    }
    for (auto zone : UDP_ZONES) {
        mUdp[zone] = std::nullopt;
    }
}

void MainWindow::updateProgress() {
    size_t done = 0;
    size_t total = 0;
    for (auto zone : ZONES) {
        done += mCells->at(size_t(zone)).size();
        total += mSites[zone].size();
    }
    mCheck = check::Running { .done = done, .total = total, .counts = zoneCountsText(*mCells) };
}

// ---- online ----------------------------------------------------------------------------------------------------

AFuture<> MainWindow::checkOnline() {
    if (*mChecking) {
        co_return;
    }
    mChecking = true;
    mOnlineDone = false;
    mOnlineRows = {};
    resetZones();
    setStatus(Sid::VPN_QUALITY, CHECKING);
    setStatus(Sid::SPLIT, CHECKING);
    updateProgress();

    // events reach the UI thread before the coroutine resumes: both go through its queue in order
    const auto sites = mSites;
    const auto stop = mStop;
    co_await (AUI_THREADPOOL {
        runOnline(
            sites,
            [this, stop](OnlineEvent e) {
                AUI_UI_THREAD {
                    if (!*stop) {
                        handle(e);
                    }
                };
            },
            *stop);
    });
    onlineDone();
}

void MainWindow::handle(const OnlineEvent& event) {
    match(
        event, [&](const online::SiteChecked& e) { handleSite(e); },
        [&](const online::DnsServerChecked& e) { handleDns(e); },
        [&](const online::GatewayChecked& e) { handleGateway(e); },
        [&](const online::SpeedMeasured& e) { handleSpeed(e); }, [&](const online::UdpChecked& e) { handleUdp(e); },
        [&](const online::IpsDetected& e) { handleIps(e); }, [](const online::Done&) {});
}

void MainWindow::handleSite(const online::SiteChecked& e) {
    const auto& r = e.result;
    const auto dns = match(
        r.dns,
        [](const Resolved& d) {
            return Cell { .value = cut(join(d.ips, ", "), 26), .color = theme::textColor(Severity::OK) };
        },
        [](const Failure& f) {
            return Cell { .value = failCell(f.error, 22), .color = theme::textColor(Severity::BAD) };
        });
    const auto tcp = match(
        r.tcp,
        [](Ms ms) { return Cell { .value = "ok {}мс"_format(ms1(ms)), .color = theme::textColor(Severity::OK) }; },
        [](const Failure& f) {
            return Cell { .value = failCell(f.error, 22), .color = theme::textColor(Severity::BAD) };
        });
    mOnlineRows.writeScope()->push_back({
      Cell { .value = AString(zoneShortName(r.zone)) },
      Cell { .value = r.name },
      Cell { .value = r.host },
      dns,
      tcp,
      httpCell(r.http),
      httpCell(r.httpDirect),
    });

    const bool reachable = siteReachable(r);
    auto& model = *mZones[r.zone];
    {
        auto z = model.stats.writeScope();
        if (auto d = std::get_if<Resolved>(&r.dns)) {
            z->dnsMs << d->rtt.count();
        }
        if (reachable) {
            ++z->ok;
            if (auto rtt = std::get_if<Ms>(&r.tcp); rtt && rtt->count() > 0) {
                z->lats << rtt->count();   // honest TCP ping
            }
        }
    }
    // the ping history gets the mean without outliers (IQR) after every site
    if (auto avg = filteredAvg(model.stats->lats)) {
        auto history = model.pingHistory.writeScope();
        *history << *avg;
        if (history->size() > 60) {
            history->erase(history->begin(), history->end() - 60);
        }
    }
    mCells.writeScope()->at(size_t(r.zone)) << reachable;
    updateProgress();
}

void MainWindow::handleDns(const online::DnsServerChecked& e) {
    const auto cell = match(
        e.result, [](const DnsAnswer& a) { return "ok {}мс {}"_format(ms1(a.rtt), cut(join(a.ips, ", "), 20)); },
        [](const Failure& f) { return failCell(f.error, 26); });
    mOnlineRows.writeScope()->push_back({
      Cell { .value = "DNS" },
      Cell { .value = e.label },
      Cell { .value = e.server },
      Cell { .value = cell },
    });
}

void MainWindow::handleGateway(const online::GatewayChecked& e) {
    const auto cell = match(
        e.result, [](const AOptional<int>& ms) { return ms ? "ok {}мс"_format(*ms) : AString("ok"); },
        [](const Failure& f) { return "× " + f.error; });
    mOnlineRows.writeScope()->push_back({
      Cell { .value = "Шлюз" },
      Cell {},
      Cell { .value = e.gateway },
      Cell { .value = cell },
    });
}

void MainWindow::handleSpeed(const online::SpeedMeasured& e) {
    auto& model = *mZones[e.zone];
    match(
        e.result,
        [&](const Speed& s) {
            model.stats.writeScope()->speed = s;
            *model.speedHistory.writeScope() << s.mbps;
        },
        [&](const Failure& f) { model.stats.writeScope()->speed = f; });
    updateVpnQuality();
}

void MainWindow::handleUdp(const online::UdpChecked& e) {
    mUdp[e.zone] = match(
        e.result,
        [](const UdpZoneOk& u) {
            AVector<AString> ports;
            for (auto p : u.ports) {
                ports << AString::number(p);
            }
            return Verdict {
                .value =
                    "{} мс · потери {}% · порты {}"_format(std::lround(u.rtt), std::lround(u.loss), join(ports, ", ")),
                .severity = udpSeverity(u.rtt, u.loss),
            };
        },
        [](const UdpZoneFailed& f) { return Verdict { .value = f.error, .severity = Severity::BAD }; });
}

void MainWindow::handleIps(const online::IpsDetected& e) {
    for (auto zone : ZONES) {
        mZones[zone]->ip = e.zones[zone];
    }
    setStatus(Sid::SPLIT, splitTunnelingStatus(e.zones, mVpnActive));
}

void MainWindow::onlineDone() {
    mOnlineDone = true;
    size_t done = 0;
    size_t total = 0;
    for (auto zone : ZONES) {
        done += mCells->at(size_t(zone)).size();
        total += mSites[zone].size();
    }
    mCheck = check::Finished { "Проверка завершена в {} · {}/{} сайтов"_format(nowText("%H:%M:%S"), done, total) };
    mStatusText = "Готово · " + nowText("%H:%M:%S");
    PerZone<ZoneStats> zones;
    for (auto zone : ZONES) {
        zones[zone] = *mZones[zone]->stats;
    }
    setStatus(
        Sid::DIAGNOSIS,
        vpnDiagnosis(zones, mVpnActive).valueOr(Verdict { .value = "В норме", .severity = Severity::OK }));
    mChecking = false;
}
