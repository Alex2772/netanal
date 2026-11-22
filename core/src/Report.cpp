#include "Report.h"

#include <array>
#include <ctime>

#include <AUI/IO/AFileOutputStream.h>
#include <AUI/Json/AJson.h>

#include "Platform.h"
#include "Shell.h"

namespace net {

namespace {

const AString RULE(70, '=');

AJson toJson(const Table& table) {
    AJson::Array columns;
    for (const auto& c : table.columns) {
        columns.push_back(c);
    }
    AJson::Array rows;
    for (const auto& row : table.rows) {
        AJson::Array cells;
        for (const auto& cell : row) {
            cells.push_back(cell);
        }
        rows.push_back(std::move(cells));
    }
    return AJson::Object { { "name", table.name }, { "columns", std::move(columns) }, { "rows", std::move(rows) } };
}

AJson toJson(const Section& section) {
    AJson::Array tables;
    for (const auto& t : section.tables) {
        tables.push_back(toJson(t));
    }
    return AJson::Object { { "tables", std::move(tables) }, { "text", section.text } };
}

}   // namespace

AString nowText(AStringView format) {
    const auto now = std::time(nullptr);
    const auto local = platform::localTime(now);
    std::array<char, 64> buffer {};
    const auto n = std::strftime(buffer.data(), buffer.size(), std::string(format).c_str(), &local);
    return AString(std::string_view(buffer.data(), n));
}

AString renderText(const SystemSnapshot& snapshot, std::span<const Finding> findings) {
    AVector<AString> out;
    out << RULE;
    out << "NetAnal — отчёт о сетевой конфигурации {}"_format(platform::osName());
    out << "Сгенерировано: " + nowText();
    out << "Запуск от администратора: " + AString(isAdmin() ? "да" : "нет");
    out << RULE;

    if (findings.empty()) {
        out << "\nНАХОДКИ: явных проблем не обнаружено";
    } else {
        out << "\nНАХОДКИ:";
        for (const auto& f : findings) {
            out << "  [{}] {}"_format(AString(levelName(f.level)).uppercase(), f.message);
        }
    }

    for (const auto& section : snapshot.sections) {
        out << "\n" + RULE;
        out << "## " + section.title;
        out << RULE;
        for (const auto& t : section.tables) {
            out << "\n-- " + t.name;
            out << join(t.columns, " | ");
            for (const auto& row : t.rows) {
                out << join(row, " | ");
            }
        }
        if (!section.text.empty()) {
            out << "\n" + section.text;
        }
    }
    return join(out, "\n");
}

bool exportReport(const APath& path, const SystemSnapshot& snapshot, std::span<const Finding> findings) {
    AJson::Array findingsJson;
    for (const auto& f : findings) {
        findingsJson.push_back(AJson::Object { { "severity", AString(levelName(f.level)) }, { "message", f.message } });
    }
    AJson::Object sections;
    for (const auto& s : snapshot.sections) {
        sections[s.title] = toJson(s);
    }
    const AJson payload = AJson::Object {
        { "generated", nowText() },
        { "admin", isAdmin() },
        { "findings", std::move(findingsJson) },
        { "sections", std::move(sections) },
        { "online", AJson::Object {} },
    };
    try {
        AFileOutputStream(path) << AJson::toString(payload);
        return true;
    } catch (const AException&) {
        return false;
    }
}

}   // namespace net
