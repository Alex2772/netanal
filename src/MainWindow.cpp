#include "MainWindow.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Action/AMenu.h>
#include <AUI/Platform/ADesktop.h>
#include <AUI/Thread/AFutureCpp20Coro.h>
#include <AUI/Thread/AThreadPool.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/AScrollArea.h>

#include "Match.h"
#include "main_window/Common.h"
#include "Platform.h"
#include "Shell.h"
#include "Report.h"
#include "SiteListDialog.h"

using namespace ass;
using namespace declarative;
using namespace net;
using namespace main_window;

namespace {

constexpr auto MONITOR_PERIOD = std::chrono::seconds(60);
constexpr auto SPEED_PAUSE = std::chrono::seconds(300);

struct TunnelProbe {
    MonitorResult result;
    bool speedMeasured = false;
};

/// The monitor check; the speed test runs only when in doubt, and at most once per SPEED_PAUSE.
TunnelProbe probeTunnel(bool speedAllowed) {
    auto r = monitorProbe();
    if (r.state != MonitorState::SUSPECT) {
        return { .result = std::move(r) };
    }
    if (!speedAllowed) {
        r.checks << MonitorCheck { .label = "Скорость", .value = "не мерили (пауза)", .severity = Severity::NEUTRAL };
        return { .result = std::move(r) };
    }
    const auto urls = speedEndpoints(Zone::FOREIGN);
    const auto sp = speedTest(urls);
    if (auto s = std::get_if<Speed>(&sp); s && s->mbps >= 5.0) {
        r.checks << MonitorCheck {
            .label = "Скорость", .value = "{:.0f} Мбит/с"_format(s->mbps), .severity = Severity::OK
        };
        r.state = MonitorState::OK;
        r.detail = "{}, скорость {:.1f} Мбит/с"_format(r.detail, s->mbps);
    } else {
        r.checks << MonitorCheck { .label = "Скорость", .value = "низкая", .severity = Severity::BAD };
        r.state = MonitorState::BAD;
        r.detail = "туннель нестабилен ({})"_format(r.detail);
    }
    return { .result = std::move(r), .speedMeasured = true };
}

}   // namespace

MainWindow::MainWindow()
  : AWindow("NetAnal — диагностика сети {}"_format(platform::osTitle()), 1180_dp, 800_dp),
    mSites(loadSiteLists()),
    mAccent(theme::ACCENTS[0].color) {
    theme::apply(*mAccent, *mDark);
    for (auto zone : ZONES) {
        mZones[zone] = _new<ZoneModel>();
        mZones[zone]->stats = ZoneStats { .total = mSites[zone].size() };
    }

    setContents(Vertical {
        Horizontal {
            emoji("bolt", 20_dp),
            text("NETANAL", { ".w800" }, 21_dp),
            text("диагностика туннеля · сети · DNS", { ".muted" }, 12_dp),
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } },
        ActivityBar { AUI_REACT(*mChecking) },
        header(),
        Label { AUI_REACT(*mStatusText) } AUI_OVERRIDE_STYLE { TextColor { rgb(0x757575) } },
        TabView {
            .tabs = {
                {
                    .title = "Главная",
                    .content = AScrollArea::Builder().withContents(dashboard()).withExpanding().build(),
                },
                { .title = "Сводка", .content = summaryTab() },
                { .title = "Система", .content = systemTab() },
            },
        } AUI_OVERRIDE_STYLE { Expanding {} },
        footer(),
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } });

    mTray = std::make_unique<Tray>(Tray::Actions {
        .onOpen = [this] { showNormal(); },
        .onQuit = [this] { quitApp(); },
    });
    mTray->setToolTip("NetAnal");

    connect(mAccent.changed, me::applyTheme);
    connect(mDark.changed, me::applyTheme);
    connect(mDark.changed, [this](bool dark) { mModeIcon = dark ? "moon" : "sun"; });
    connect(mMonitorEnabled.changed, me::setMonitorEnabled);

    mTasks << refreshAll();
    mTasks << countdownLoop();
    setMonitorEnabled(true);
}

MainWindow::~MainWindow() { *mStop = true; }

// ---- theme -----------------------------------------------------------------------------------------------------

void MainWindow::applyTheme() {
    theme::apply(*mAccent, *mDark);
    // resets the cached rules of every view in the window
    setExtraStylesheet(_new<AStylesheet>() AUI_LET { it->setRules({}); });
    redraw();
}

void MainWindow::showAccentMenu() {
    AMenuModel model;
    for (const auto& accent : theme::ACCENTS) {
        model << AMenuItem {
            .name = AString(accent.name),
            .onAction = [this, color = accent.color] { mAccent = color; },
        };
    }
    AMenu::show(model);
}

// ---- tray ------------------------------------------------------------------------------------------------------

void MainWindow::onCloseButtonClicked() {
    if (!mTray->hasIcon()) {
        quitApp();
        return;
    }
    // minimise to the tray instead of quitting
    hide();
    mTray->showMessage("NetAnal", "Свёрнуто в трей — утилита продолжает следить за туннелем.", Tray::Kind::INFO);
}

void MainWindow::showNormal() {
    show();
    activate();
}

void MainWindow::quitApp() {
    *mStop = true;
    mMonitorLoop.reset();
    close();
}

// ---- monitor ---------------------------------------------------------------------------------------------------

void MainWindow::setMonitorEnabled(bool enabled) {
    if (enabled) {
        mMonitorLoop = monitorLoop();
        return;
    }
    mMonitorLoop.reset();   // cancels the loop
    mMonitor = std::nullopt;
    mMonitorLast = "—";
    mTray->setColor(theme::MONITOR_OFF);
    mTray->setToolTip("NetAnal — мониторинг выключен");
}

AFuture<> MainWindow::monitorLoop() {
    for (;;) {
        mMonitorNext = Clock::now() + MONITOR_PERIOD;
        const bool speedAllowed = !mLastSpeed || Clock::now() - *mLastSpeed >= SPEED_PAUSE;
        auto probe = co_await (AUI_THREADPOOL { return probeTunnel(speedAllowed); });
        if (probe.speedMeasured) {
            mLastSpeed = Clock::now();
        }
        applyMonitor(std::move(probe.result));
        const auto remaining = std::max(Clock::duration {}, mMonitorNext - Clock::now());
        co_await AThread::asyncSleep(std::chrono::duration_cast<std::chrono::milliseconds>(remaining));
    }
}

AFuture<> MainWindow::countdownLoop() {
    for (;;) {
        if (*mMonitorEnabled) {
            const auto left = std::chrono::duration_cast<std::chrono::seconds>(mMonitorNext - Clock::now()).count();
            mSecondsLeft = int(std::max<long>(0, left));
        } else {
            mSecondsLeft = std::nullopt;
        }
        co_await AThread::asyncSleep(std::chrono::seconds(1));
    }
}

void MainWindow::applyMonitor(MonitorResult result) {
    const auto prev = mMonitor->map([](const MonitorResult& r) { return r.state; });
    const auto color = monitorColor(result);
    mTray->setColor(color);
    mTray->setToolTip("NetAnal — {}: {}"_format(monitorStateName(result.state), result.detail));
    if (result.state == MonitorState::BAD && prev != MonitorState::BAD) {
        mTray->showMessage("NetAnal", "⚠️ Туннель нестабилен: " + result.detail, Tray::Kind::WARNING);
    }
    if (!result.detail.empty()) {
        mMonitorLast = nowText("%H:%M:%S");
    }
    const auto state = result.state;
    mMonitor = std::move(result);
    // the VPN came up: run the full check again
    if (prev == MonitorState::OFF && state != MonitorState::OFF) {
        mStatusText = "VPN включён — запускаю полную проверку…";
        mTasks << refreshAll();
    }
}

// ---- site lists and export -------------------------------------------------------------------------------------

AFuture<> MainWindow::editSiteLists() {
    const auto lists = co_await SiteListDialog::ask(*this, mSites);
    if (!lists) {
        co_return;
    }
    if (std::any_of(lists->begin(), lists->end(), [](const auto& l) { return l.empty(); })) {
        mStatusText = "Пустой список зоны — изменения не сохранены";
        co_return;
    }
    if (!saveSiteLists(*lists)) {
        mStatusText = "Не удалось записать sites.json";
        co_return;
    }
    mSites = loadSiteLists();
    AVector<AString> counts;
    for (auto zone : ZONES) {
        counts << "{}: {}"_format(zoneName(zone), mSites[zone].size());
    }
    mStatusText = "Списки сохранены ({}) · запускаю проверку"_format(join(counts, ", "));
    mTasks << checkOnline();
}

AFuture<> MainWindow::exportReport() {
    const auto dir = co_await ADesktop::browseForDir(this);
    if (dir.empty()) {
        co_return;
    }
    const auto path = dir / "netanal-report.json";
    if (net::exportReport(path, *mSnapshot, *mFindings)) {
        setTitle("NetAnal — отчёт сохранён: {}"_format(path));
    }
}
