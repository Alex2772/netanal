#include "MainWindow.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/ACheckBox.h>
#include <AUI/View/ADrawableView.h>
#include <AUI/View/AScrollArea.h>
#include <AUI/View/ATabView.h>

#include "Match.h"
#include "main_window/Common.h"
#include "Report.h"
#include "Shell.h"

using namespace ass;
using namespace declarative;
using namespace net;
using namespace main_window;

namespace {

constexpr auto HINTS = std::to_array<AStringView>({
    "Маршрут в туннель при выключенном VPN — подними метрику адаптера.",
    "Сломанный Winsock: netsh winsock reset + перезагрузка.",
    "Мусорные TUN/TAP — удали в Диспетчере устройств (показать скрытые).",
    "Остаточный прокси — Параметры → Сеть → Прокси.",
    "DNS: ipconfig /flushdns, проверь NRPT и DoH.",
    "MTU при обрывах: 1400–1420 на туннельном адаптере.",
});

/// Rows of the "IP-адреса" card.
constexpr auto IP_ROWS = std::to_array<std::pair<AStringView, Zone>>({
    { "В РФ", Zone::RU },
    { "Наружу", Zone::FOREIGN },
    { "Заблокированные", Zone::BLOCKED },
});

constexpr AStringView ADMIN_TEXT = "права администратора";
constexpr AStringView NO_ADMIN_TEXT = "без прав администратора (часть данных недоступна)";

AString ipText(const AOptional<ZoneIp>& z) {
    if (!z) {
        return "…";
    }
    if (!z->ip) {
        return "—";
    }
    if (z->geo && !z->geo->country.empty()) {
        return "{} · {}"_format(*z->ip, z->geo->country);
    }
    return *z->ip;
}

_<AView> sectionHeader(AStringView icon, const AString& title) {
    return Horizontal { emoji(icon, 16_dp), text(title, { ".w700" }, 15_dp) } AUI_LET {
        it->addAssName(".section_header");
        it->setCustomStyle({ LayoutSpacing { 6_dp } });
    };
}

_<AView> iconButton(_<AView> icon, std::function<void()> onClick) {
    return Button { .content = std::move(icon), .onClick = std::move(onClick) } AUI_OVERRIDE_STYLE {
        Padding { 8_dp, 12_dp },
    };
}

_<AView> findingRow(AColor color, AStringView icon, const AString& message) {
    return Horizontal { emoji(icon, 15_dp), wrapped(message) } AUI_LET {
        it->addAssName(".finding");
        it->setCustomStyle({ BorderLeft { 3_dp, color }, LayoutSpacing { 8_dp } });
    };
}

_<AView> findingsList(const AVector<Finding>& findings) {
    _<AViewContainer> box = Vertical {} AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
    if (findings.empty()) {
        box->addView(findingRow(theme::textColor(Severity::OK), "check", "Явных проблем не обнаружено."));
    }
    for (const auto& f : findings) {
        switch (f.level) {
            case Level::ERR:
                box->addView(findingRow(theme::textColor(Severity::BAD), "cross", f.message));
                break;
            case Level::WARN:
                box->addView(findingRow(theme::textColor(Severity::WARN), "warning", f.message));
                break;
            case Level::INFO:
                box->addView(findingRow(theme::INFO_BLUE, "info", f.message));
                break;
        }
    }
    return box;
}

_<AView> hintsList() {
    _<AViewContainer> box = Vertical {
        Horizontal { emoji("bulb", 14_dp), text("Подсказки", { ".muted", ".w700" }) }
            AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp }, Margin { 10_dp, 0, 0 } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
    for (auto hint : HINTS) {
        box->addView(wrapped("• " + AString(hint)) AUI_LET {
            it->setCustomStyle({ TextColor { theme::MUTED_GREY }, FontSize { 12_dp }, Expanding { 1, 0 } });
        });
    }
    return box;
}

_<AView> sectionView(const Section& section) {
    _<AViewContainer> page = Vertical {} AUI_OVERRIDE_STYLE { Padding { 6_dp }, LayoutSpacing { 4_dp } };
    if (section.tables.empty() && section.text.empty()) {
        page->addView(Centered {
            text("— нет данных —") AUI_LET {
                it->setCustomStyle({ TextColor { rgb(0x607d8b) }, FontSize { 13_dp }, Padding { 24_dp } });
            },
        });
    }
    for (const auto& table : section.tables) {
        page->addView(text(table.name, { ".muted", ".w700" }) AUI_OVERRIDE_STYLE { Margin { 6_dp, 0, 0 } });
        page->addView(fitTable(table.columns, table.rows));
    }
    if (section.text.empty()) {
        return page;
    }
    _<AViewContainer> textBox = Vertical {};
    for (const auto& line : lines(section.text)) {
        textBox->addView(text(line.empty() ? AString(" ") : line));
    }
    page->addView(AScrollArea::Builder().withContents(textBox).build() AUI_LET {
        it->addAssName(".textbox");
        it->setCustomStyle({ MaxSize { {}, 220_dp }, Expanding { 1, 0 } });
    });
    return page;
}

AString monitorFooter(const AOptional<MonitorResult>& result, bool enabled) {
    if (!enabled) {
        return "мониторинг выключен";
    }
    if (!result) {
        return "мониторинг активен";
    }
    switch (result->state) {
        case MonitorState::OK:
            return "туннель в норме";
        case MonitorState::SUSPECT:
            return "есть сомнения";
        case MonitorState::BAD:
            return "туннель нестабилен";
        case MonitorState::OFF:
            break;
    }
    return "VPN выключен";
}

}   // namespace

_<AView> MainWindow::header() {
    const bool admin = isAdmin();
    return Horizontal {
        Button {
            .content =
                Horizontal {
                    Icon { AUI_REACT(emojiUrl(*mChecking ? "hourglass" : "play")) }
                        AUI_OVERRIDE_STYLE { FixedSize { 14_dp, 14_dp } },
                    Label { AUI_REACT(AString(*mChecking ? "Проверка…" : "Проверить всё")) },
                } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } },
            .onClick = [this] { mTasks << refreshAll(); },
        } AUI_LET {
            it->addAssName(".primary");
            connect(AUI_REACT(!*mChecking), AUI_SLOT(it)::setEnabled);
        },
        CheckBox {
            .checked = AUI_REACT(*mMonitorEnabled),
            .onCheckedChange = [this](bool checked) { mMonitorEnabled = checked; },
            .content = Label { "Мониторинг туннеля (60 с)" },
        },
        iconButton(emoji("palette", 16_dp), [this] { showAccentMenu(); }),
        iconButton(Icon { AUI_REACT(emojiUrl(*mModeIcon)) } AUI_OVERRIDE_STYLE { FixedSize { 16_dp, 16_dp } },
                   [this] { mDark = !*mDark; }),
        Button {
            .content = Horizontal { emoji("clipboard", 16_dp), Label { "Списки" } }
                AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } },
            .onClick = [this] { mTasks << editSiteLists(); },
        },
        SpacerExpanding {},
        Horizontal {
            Centered { emoji(admin ? "bolt" : "warning", 14_dp) },
            text(AString(admin ? ADMIN_TEXT : NO_ADMIN_TEXT))
                AUI_OVERRIDE_STYLE { TextColor { admin ? rgb(0x66bb6a) : rgb(0xef5350) } },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 4_dp } },
        Button { .content = Label { "Сохранить отчёт…" }, .onClick = [this] { mTasks << exportReport(); } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
}

_<AView> MainWindow::footer() {
    return Horizontal {
        Dot { AUI_REACT(*mMonitorEnabled ? monitorColor(*mMonitor) : theme::MONITOR_OFF), 8_dp },
        Caption {
            .text = AUI_REACT(monitorFooter(*mMonitor, *mMonitorEnabled)),
            .color = AUI_REACT(*mMonitorEnabled && *mMonitor ? monitorColor(*mMonitor) : rgb(0x607d8b)),
        },
        SpacerExpanding {},
        text("NetAnal · v1.0") AUI_OVERRIDE_STYLE { FontSize { 12_dp }, TextColor { rgb(0x455a64) } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp } };
}

_<AView> MainWindow::statusCard(AStringView icon, const AString& title, std::initializer_list<Sid> ids) {
    AVector<DetailRow> rows;
    for (auto id : ids) {
        rows << DetailRow {
            .label = AString(spec(id).row),
            .value = AUI_REACT(status(id)),
            .country = id == Sid::RESOLVER ? In<AString>(AUI_REACT(*mResolverCountry)) : In<AString>(AString()),
        };
    }
    return DetailCard { .icon = icon, .title = title, .rows = std::move(rows) }();
}

_<AView> MainWindow::dashboard() {
    _<AViewContainer> zones = Horizontal {} AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } };
    for (auto zone : ZONES) {
        zones->addView(ZoneCard { .zone = zone, .model = mZones[zone], .accent = AUI_REACT(*mAccent) });
    }

    AVector<DetailRow> ipRows;
    for (const auto& [label, zone] : IP_ROWS) {
        const auto& model = mZones[zone];
        ipRows << DetailRow {
            .label = AString(label),
            .value = AUI_REACT(Verdict { ipText(*model->ip) }),
            .country = AUI_REACT(*model->ip ? geoCountry((*model->ip)->geo) : AString()),
        };
    }
    AVector<DetailRow> udpRows;
    for (auto zone : UDP_ZONES) {
        udpRows << DetailRow { .label = AString(zoneName(zone)), .value = AUI_REACT(mUdp[zone]->valueOr(PENDING)) };
    }

    return Vertical {
        Horizontal {
            SummaryCard {
                .state = AUI_REACT(summaryState()),
                .items = AUI_REACT(summaryItems()),
                .progress = AUI_REACT(*mCheck),
            },
            MonitorCard {
                .result = AUI_REACT(*mMonitor),
                .lastCheck = AUI_REACT(*mMonitorLast),
                .secondsLeft = AUI_REACT(*mSecondsLeft),
                .enabled = AUI_REACT(*mMonitorEnabled),
                .onToggle = [this] { mMonitorEnabled = !*mMonitorEnabled; },
            },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } },
        sectionHeader("pin", "Доступность по зонам"),
        zones,
        Horizontal {
            statusCard("lock", "VPN и маршрутизация",
                       { Sid::VPN, Sid::ROUTE, Sid::SPLIT, Sid::VPN_QUALITY, Sid::DIAGNOSIS }),
            statusCard("compass", "DNS", { Sid::DNS_LIVE, Sid::RESOLVER, Sid::SPLIT_DNS, Sid::CENSORSHIP, Sid::CACHE }),
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } },
        Horizontal {
            DetailCard { .icon = "globe", .title = "IP-адреса", .rows = std::move(ipRows) },
            statusCard("gear", "Система", { Sid::PROXY, Sid::ADAPTERS }),
            DetailCard { .icon = "gamepad", .title = "UDP (игры)", .rows = std::move(udpRows) },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } },
        wrapped("Доступно = ответило >= 80% сайтов зоны. Скорость — многопоточная загрузка, пинг — минимальный "
                "TCP-RTT.") AUI_OVERRIDE_STYLE { TextColor { rgb(0x757575) }, Expanding { 1, 0 } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp }, Padding { 0, 4_dp, 0, 0 } };
}

_<AView> MainWindow::summaryTab() {
    return AScrollArea::Builder()
        .withContents(Vertical {
            Dynamic<AVector<Finding>> { .value = AUI_REACT(*mFindings), .view = findingsList },
            hintsList(),
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 6_dp }, Padding { 4_dp } })
        .withExpanding()
        .build();
}

_<AView> MainWindow::systemTab() {
    struct Nav {
        AVector<AString> titles;
        size_t selected;
    };
    auto nav = Dynamic<Nav> {
        .value =
            AUI_REACT([&] {
                Nav n { .titles = { "Онлайн (детально)" }, .selected = *mSystemIndex };
                for (const auto& s : mSnapshot->sections) {
                    n.titles << s.title;
                }
                return n;
            }()),
        .view =
            [this](const Nav& n) {
                _<AViewContainer> list = Vertical {};
                for (size_t i = 0; i < n.titles.size(); ++i) {
                    list->addView(text(n.titles[i], { ".navitem" }) AUI_LET {
                        it->setCustomStyle({ Expanding { 1, 0 } });
                        it->setAssName(".navitem_selected", i == n.selected);
                        connect(it->clicked, [this, i] { mSystemIndex = i; });
                    });
                }
                return list;
            },
    }() AUI_LET {
        it->addAssName(".navlist");
        it->setCustomStyle({ FixedSize { 190_dp, {} } });
    };

    auto onlineTable = StretchTable {
        .columns = { "Зона", "Проверка", "Цель", "DNS", "TCP 443", "HTTP (прокси)", "HTTP (напрямую)" },
        .rows = AUI_REACT(*mOnlineRows),
    }();
    auto page = AScrollArea::Builder().withExpanding().build() AUI_OVERRIDE_STYLE {
        ScrollbarAppearance { ScrollbarAppearance::ON_DEMAND, ScrollbarAppearance::NEVER },
    };
    connect(AUI_REACT(*mSystemIndex), [this, page = page.get(), onlineTable](size_t index) {
        if (index == 0 || index > mSnapshot->sections.size()) {
            page->setContents(Vertical { onlineTable } AUI_OVERRIDE_STYLE { Padding { 4_dp } });
            return;
        }
        page->setContents(sectionView(mSnapshot->sections[index - 1]));
    });
    connect(mSnapshot.changed, [this] { mSystemIndex.notify(); });

    return Horizontal {
        AScrollArea::Builder().withContents(nav).build()
            AUI_OVERRIDE_STYLE { FixedSize { 190_dp, {} }, Expanding { 0, 1 } },
        page,
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp }, Padding { 4_dp, 0, 0 } };
}
