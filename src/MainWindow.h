#pragma once

#include <atomic>
#include <chrono>

#include <AUI/Common/AProperty.h>
#include <AUI/Platform/AWindow.h>
#include <AUI/Thread/AAsyncHolder.h>
#include <AUI/Thread/AFuture.h>

#include "Dns.h"
#include "Online.h"
#include "System.h"
#include "Tray.h"
#include "Verdicts.h"
#include "Widgets.h"

/// Items of the dashboard status, in the order the original's dict holds them.
enum class Sid {
    VPN,
    ROUTE,
    PROXY,
    CACHE,
    WINSOCK,
    ADAPTERS,
    DNS_LIVE,
    RESOLVER,
    SPLIT_DNS,
    CENSORSHIP,
    VPN_QUALITY,
    SPLIT,
    DIAGNOSIS,
    COUNT,
};

class MainWindow : public AWindow {
public:
    MainWindow();
    ~MainWindow() override;

protected:
    void onCloseButtonClicked() override;

private:
    using Clock = std::chrono::steady_clock;

    // configuration and findings
    AProperty<net::SystemSnapshot> mSnapshot;
    AProperty<AVector<net::Finding>> mFindings;
    AProperty<size_t> mSystemIndex = 0;
    bool mVpnActive = false;
    bool mCollecting = false;

    // dashboard
    std::array<AProperty<AOptional<net::Verdict>>, size_t(Sid::COUNT)> mStatus;
    AProperty<AString> mResolverCountry;
    net::PerZone<AProperty<AOptional<net::Verdict>>> mUdp;
    AProperty<AString> mStatusText = "Готово";

    // online check
    net::SiteLists mSites;
    net::PerZone<_<ZoneModel>> mZones;
    AProperty<net::PerZone<AVector<bool>>> mCells;
    AProperty<AVector<AVector<Cell>>> mOnlineRows;
    AProperty<bool> mChecking = false;
    AProperty<CheckProgress> mCheck;
    bool mOnlineDone = false;
    _<std::atomic_bool> mStop = _new<std::atomic_bool>(false);

    // theme
    AProperty<AColor> mAccent;
    AProperty<bool> mDark = true;
    /// The theme button: "halfmoon" until the theme is switched for the first time.
    AProperty<AString> mModeIcon = "halfmoon";

    // monitor
    AProperty<bool> mMonitorEnabled = true;
    AProperty<AOptional<net::MonitorResult>> mMonitor;
    AProperty<AString> mMonitorLast = "—";
    AProperty<AOptional<int>> mSecondsLeft;
    Clock::time_point mMonitorNext;
    AOptional<Clock::time_point> mLastSpeed;
    AOptional<AFuture<>> mMonitorLoop;

    std::unique_ptr<Tray> mTray;
    AAsyncHolder mTasks;

    _<AView> header();
    _<AView> dashboard();
    _<AView> summaryTab();
    _<AView> systemTab();
    _<AView> footer();
    _<AView> statusCard(AStringView icon, const AString& title, std::initializer_list<Sid> ids);

    [[nodiscard]] net::Verdict status(Sid id) const;
    void setStatus(Sid id, net::Verdict verdict);
    [[nodiscard]] AVector<SummaryItem> summaryItems() const;
    [[nodiscard]] SummaryState summaryState() const;

    AFuture<> refreshAll();
    AFuture<> checkDns();
    AFuture<> checkSplitDns();
    AFuture<> checkOnline();
    void populateStatus();
    void resetZones();
    void updateProgress();
    void updateVpnQuality();

    void handle(const net::OnlineEvent& event);
    void handleSite(const net::online::SiteChecked& e);
    void handleDns(const net::online::DnsServerChecked& e);
    void handleGateway(const net::online::GatewayChecked& e);
    void handleSpeed(const net::online::SpeedMeasured& e);
    void handleUdp(const net::online::UdpChecked& e);
    void handleIps(const net::online::IpsDetected& e);
    void onlineDone();

    void applyTheme();
    void showAccentMenu();

    void showNormal();
    void quitApp();

    void setMonitorEnabled(bool enabled);
    AFuture<> monitorLoop();
    AFuture<> countdownLoop();
    void applyMonitor(net::MonitorResult result);

    AFuture<> editSiteLists();
    AFuture<> exportReport();
};
