#include "Sites.h"

#include <AUI/IO/AFileInputStream.h>
#include <AUI/IO/AFileOutputStream.h>
#include <AUI/Json/AJson.h>
#include <AUI/Platform/AProcess.h>

namespace net {

namespace {

const PerZone<AVector<Site>> DEFAULTS = { {
    AVector<Site> {
        { "Яндекс", "https://ya.ru" },
        { "VK", "https://vk.com" },
        { "Mail.ru", "https://mail.ru" },
        { "Госуслуги", "https://www.gosuslugi.ru" },
        { "Сбербанк", "https://www.sberbank.ru" },
        { "РБК", "https://www.rbc.ru" },
        { "Ozon", "https://www.ozon.ru" },
        { "Wildberries", "https://www.wildberries.ru" },
        { "Avito", "https://www.avito.ru" },
        { "Rambler", "https://www.rambler.ru" },
        { "Лента", "https://lenta.ru" },
        { "2ГИС", "https://2gis.ru" },
        { "Тинькофф", "https://www.tinkoff.ru" },
        { "Кинопоиск", "https://www.kinopoisk.ru" },
        { "РИА", "https://ria.ru" },
        { "Газета.ру", "https://www.gazeta.ru" },
        { "Коммерсантъ", "https://www.kommersant.ru" },
        { "Ведомости", "https://www.vedomosti.ru" },
        { "Яндекс.Маркет", "https://market.yandex.ru" },
        { "Дзен", "https://dzen.ru" },
        { "Мегафон", "https://www.megafon.ru" },
        { "МТС", "https://www.mts.ru" },
        { "Пикабу", "https://pikabu.ru" },
        { "Хабр", "https://habr.com" },
        { "Почта России", "https://www.pochta.ru" },
    },
    AVector<Site> {
        { "Microsoft", "https://www.microsoft.com" },
        { "Apple", "https://www.apple.com" },
        { "Cloudflare", "https://www.cloudflare.com" },
        { "Википедия", "https://ru.wikipedia.org" },
        { "GitHub", "https://github.com" },
        { "OpenAI", "https://openai.com" },
        { "Amazon", "https://www.amazon.com" },
        { "Netflix", "https://www.netflix.com" },
        { "Reddit", "https://www.reddit.com" },
        { "StackOverflow", "https://stackoverflow.com" },
        { "DuckDuckGo", "https://duckduckgo.com" },
        { "Dropbox", "https://www.dropbox.com" },
        { "Google", "https://www.google.com" },
        { "Bing", "https://www.bing.com" },
        { "Yahoo", "https://www.yahoo.com" },
        { "Spotify", "https://www.spotify.com" },
        { "Twitch", "https://www.twitch.tv" },
        { "Adobe", "https://www.adobe.com" },
        { "WordPress", "https://wordpress.com" },
        { "Archive.org", "https://archive.org" },
        { "BBC", "https://www.bbc.com" },
        { "CNN", "https://edition.cnn.com" },
        { "Reuters", "https://www.reuters.com" },
        { "Python", "https://www.python.org" },
        { "Mozilla", "https://www.mozilla.org" },
    },
    AVector<Site> {
        { "Instagram", "https://www.instagram.com" },
        { "Facebook", "https://www.facebook.com" },
        { "X / Twitter", "https://x.com" },
        { "YouTube", "https://www.youtube.com" },
        { "Discord", "https://discord.com" },
        { "LinkedIn", "https://www.linkedin.com" },
        { "TikTok", "https://www.tiktok.com" },
        { "Medium", "https://medium.com" },
        { "OnlyFans", "https://onlyfans.com" },
        { "BBC", "https://www.bbc.com" },
        { "Deutsche Welle", "https://www.dw.com" },
        { "RFE/RL", "https://www.rferl.org" },
        { "Tor Project", "https://www.torproject.org" },
        { "Proton", "https://proton.me" },
        { "OpenAI", "https://openai.com" },
        { "Anthropic", "https://www.anthropic.com" },
        { "Threads", "https://www.threads.net" },
        { "Messenger", "https://www.messenger.com" },
        { "Signal", "https://signal.org" },
        { "Clubhouse", "https://www.clubhouse.com" },
        { "Meduza", "https://meduza.io" },
        { "Novaya Gazeta", "https://novayagazeta.eu" },
        { "The Insider", "https://theinsider.press" },
        { "iStories", "https://istories.media" },
        { "Bellingcat", "https://www.bellingcat.com" },
    },
} };

AVector<Site> parseZone(const AJson& items) {
    AVector<Site> result;
    if (!items.isArray()) {
        return result;
    }
    for (const auto& item : items.asArray()) {
        if (item.isString()) {
            if (auto url = AString(item.asString().trim()); !url.empty()) {
                result << Site { .name = hostOf(url), .url = std::move(url) };
            }
            continue;
        }
        if (item.isArray() && item.asArray().size() >= 2 && item.asArray()[0].isString() &&
            item.asArray()[1].isString()) {
            result << Site { .name = item.asArray()[0].asString(), .url = item.asArray()[1].asString() };
        }
    }
    return result;
}

}   // namespace

const AVector<Site>& defaultSites(Zone zone) { return DEFAULTS[zone]; }

SiteLists defaultSiteLists() { return DEFAULTS; }

AString hostOf(AStringView url) {
    auto rest = url;
    if (auto scheme = rest.find("://"); scheme != AStringView::npos) {
        rest = rest.substr(scheme + 3);
    }
    rest = rest.substr(0, rest.find_first_of("/?#"));
    if (rest.empty()) {
        return AString(url);
    }
    return AString(rest);
}

APath sitesFile() { return AProcess::self()->getPathToExecutable().parent() / "sites.json"; }

SiteLists parseSiteLists(AStringView json) {
    auto lists = defaultSiteLists();
    AJson root;
    try {
        root = AJson::fromString(AString(json));
    } catch (...) {
        return lists;
    }
    if (!root.isObject()) {
        return lists;
    }
    for (auto zone : ZONES) {
        if (auto item = root.asObject().contains(AString(zoneName(zone)))) {
            if (auto parsed = parseZone(item->second); !parsed.empty()) {
                lists[zone] = std::move(parsed);
            }
        }
    }
    return lists;
}

SiteLists loadSiteLists(const APath& file) {
    try {
        return parseSiteLists(AString::fromUtf8(AByteBuffer::fromStream(AFileInputStream(file))));
    } catch (...) {
        return defaultSiteLists();
    }
}

bool saveSiteLists(const SiteLists& lists, const APath& file) {
    AJson::Object root;
    for (auto zone : ZONES) {
        AJson::Array items;
        for (const auto& site : lists[zone]) {
            items << AJson(AJson::Array { AJson(site.name), AJson(site.url) });
        }
        root[AString(zoneName(zone))] = AJson(std::move(items));
    }
    try {
        AFileOutputStream(file) << AJson::toString(AJson(std::move(root)));
        return true;
    } catch (...) {
        return false;
    }
}

}   // namespace net
