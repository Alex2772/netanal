#include "Sites.h"

#include <AUI/IO/AFileInputStream.h>
#include <AUI/IO/AFileOutputStream.h>
#include <AUI/Json/AJson.h>
#include <AUI/Platform/AProcess.h>

namespace net {

namespace {

const PerZone<AVector<Site>> DEFAULTS = { {
  AVector<Site> {
    { .name = "Яндекс", .url = "https://ya.ru" },
    { .name = "VK", .url = "https://vk.com" },
    { .name = "Mail.ru", .url = "https://mail.ru" },
    { .name = "Госуслуги", .url = "https://www.gosuslugi.ru" },
    { .name = "Сбербанк", .url = "https://www.sberbank.ru" },
    { .name = "РБК", .url = "https://www.rbc.ru" },
    { .name = "Ozon", .url = "https://www.ozon.ru" },
    { .name = "Wildberries", .url = "https://www.wildberries.ru" },
    { .name = "Avito", .url = "https://www.avito.ru" },
    { .name = "Rambler", .url = "https://www.rambler.ru" },
    { .name = "Лента", .url = "https://lenta.ru" },
    { .name = "2ГИС", .url = "https://2gis.ru" },
    { .name = "Тинькофф", .url = "https://www.tinkoff.ru" },
    { .name = "Кинопоиск", .url = "https://www.kinopoisk.ru" },
    { .name = "РИА", .url = "https://ria.ru" },
    { .name = "Газета.ру", .url = "https://www.gazeta.ru" },
    { .name = "Коммерсантъ", .url = "https://www.kommersant.ru" },
    { .name = "Ведомости", .url = "https://www.vedomosti.ru" },
    { .name = "Яндекс.Маркет", .url = "https://market.yandex.ru" },
    { .name = "Дзен", .url = "https://dzen.ru" },
    { .name = "Мегафон", .url = "https://www.megafon.ru" },
    { .name = "МТС", .url = "https://www.mts.ru" },
    { .name = "Пикабу", .url = "https://pikabu.ru" },
    { .name = "Хабр", .url = "https://habr.com" },
    { .name = "Почта России", .url = "https://www.pochta.ru" },
  },
  AVector<Site> {
    { .name = "Microsoft", .url = "https://www.microsoft.com" },
    { .name = "Apple", .url = "https://www.apple.com" },
    { .name = "Cloudflare", .url = "https://www.cloudflare.com" },
    { .name = "Википедия", .url = "https://ru.wikipedia.org" },
    { .name = "GitHub", .url = "https://github.com" },
    { .name = "OpenAI", .url = "https://openai.com" },
    { .name = "Amazon", .url = "https://www.amazon.com" },
    { .name = "Netflix", .url = "https://www.netflix.com" },
    { .name = "Reddit", .url = "https://www.reddit.com" },
    { .name = "StackOverflow", .url = "https://stackoverflow.com" },
    { .name = "DuckDuckGo", .url = "https://duckduckgo.com" },
    { .name = "Dropbox", .url = "https://www.dropbox.com" },
    { .name = "Google", .url = "https://www.google.com" },
    { .name = "Bing", .url = "https://www.bing.com" },
    { .name = "Yahoo", .url = "https://www.yahoo.com" },
    { .name = "Spotify", .url = "https://www.spotify.com" },
    { .name = "Twitch", .url = "https://www.twitch.tv" },
    { .name = "Adobe", .url = "https://www.adobe.com" },
    { .name = "WordPress", .url = "https://wordpress.com" },
    { .name = "Archive.org", .url = "https://archive.org" },
    { .name = "BBC", .url = "https://www.bbc.com" },
    { .name = "CNN", .url = "https://edition.cnn.com" },
    { .name = "Reuters", .url = "https://www.reuters.com" },
    { .name = "Python", .url = "https://www.python.org" },
    { .name = "Mozilla", .url = "https://www.mozilla.org" },
  },
  AVector<Site> {
    { .name = "Instagram", .url = "https://www.instagram.com" },
    { .name = "Facebook", .url = "https://www.facebook.com" },
    { .name = "X / Twitter", .url = "https://x.com" },
    { .name = "YouTube", .url = "https://www.youtube.com" },
    { .name = "Discord", .url = "https://discord.com" },
    { .name = "LinkedIn", .url = "https://www.linkedin.com" },
    { .name = "TikTok", .url = "https://www.tiktok.com" },
    { .name = "Medium", .url = "https://medium.com" },
    { .name = "OnlyFans", .url = "https://onlyfans.com" },
    { .name = "BBC", .url = "https://www.bbc.com" },
    { .name = "Deutsche Welle", .url = "https://www.dw.com" },
    { .name = "RFE/RL", .url = "https://www.rferl.org" },
    { .name = "Tor Project", .url = "https://www.torproject.org" },
    { .name = "Proton", .url = "https://proton.me" },
    { .name = "OpenAI", .url = "https://openai.com" },
    { .name = "Anthropic", .url = "https://www.anthropic.com" },
    { .name = "Threads", .url = "https://www.threads.net" },
    { .name = "Messenger", .url = "https://www.messenger.com" },
    { .name = "Signal", .url = "https://signal.org" },
    { .name = "Clubhouse", .url = "https://www.clubhouse.com" },
    { .name = "Meduza", .url = "https://meduza.io" },
    { .name = "Novaya Gazeta", .url = "https://novayagazeta.eu" },
    { .name = "The Insider", .url = "https://theinsider.press" },
    { .name = "iStories", .url = "https://istories.media" },
    { .name = "Bellingcat", .url = "https://www.bellingcat.com" },
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
