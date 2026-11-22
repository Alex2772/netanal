#include "SiteListDialog.h"

#include <AUI/ASS/ASS.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/AButton.h>
#include <AUI/View/AScrollArea.h>
#include <AUI/View/ATabView.h>

#include "Shell.h"
#include "Widgets.h"

using namespace ass;
using namespace declarative;
using namespace net;

namespace {

AString urlsText(const AVector<Site>& sites) {
    AVector<AString> urls;
    for (const auto& s : sites) {
        urls << s.url;
    }
    return join(urls, "\n");
}

}   // namespace

SiteListDialog::Result SiteListDialog::ask(AWindow& parent, const SiteLists& current) {
    return Result::create([&](Result::Resolver resolver) {
        _new<SiteListDialog>(parent, current, std::move(resolver))->show();
    });
}

SiteListDialog::SiteListDialog(AWindow& parent, const SiteLists& current, Result::Resolver resolver)
  : AWindow(Init {
        .title = "Списки сайтов для проверки",
        .width = 720_dp,
        .height = 560_dp,
        .parent = Init::Parent { .window = parent, .modal = true },
    }),
    mResolver(std::move(resolver)) {
    AVector<Tab> tabs;
    for (auto zone : ZONES) {
        _<ATextArea> edit = TextArea { urlsText(current[zone]) };
        mEditors[zone] = edit;
        tabs << Tab {
            .title = "{} ({})"_format(zoneName(zone), current[zone].size()),
            .content = AScrollArea::Builder().withContents(edit).withExpanding().build(),
        };
    }
    setContents(Vertical {
        wrapped("Один URL на строку. Имя берётся из домена. Списки сохраняются в sites.json рядом с утилитой.",
                { ".muted" }),
        TabView { std::move(tabs) } AUI_OVERRIDE_STYLE { Expanding {} },
        Horizontal {
            Button { .content = Label { "Сбросить к дефолтным" }, .onClick = [this] { reset(); } },
            SpacerExpanding {},
            Button {
                .content = Label { "Сохранить" },
                .onClick =
                    [this] {
                        mResolver.supplyValue(values());
                        close();
                    },
            } AUI_LET { it->addAssName(".primary"); },
            Button { .content = Label { "Отмена" }, .onClick = [this] { close(); } },
        } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } },
    } AUI_OVERRIDE_STYLE { LayoutSpacing { 8_dp } });
}

// the first result wins: after "Сохранить" this one is ignored
SiteListDialog::~SiteListDialog() { mResolver.supplyValue(std::nullopt); }

void SiteListDialog::reset() {
    for (auto zone : ZONES) {
        mEditors[zone]->setText(urlsText(defaultSites(zone)));
    }
}

SiteLists SiteListDialog::values() const {
    SiteLists out;
    for (auto zone : ZONES) {
        for (const auto& line : lines(mEditors[zone]->getText())) {
            const auto url = AString(line).trim();
            if (!url.empty()) {
                out[zone] << Site { .name = hostOf(url), .url = url };
            }
        }
    }
    return out;
}
