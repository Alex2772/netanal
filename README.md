# NetAnal

NetAnal — диагностика сетевой конфигурации и VPN-туннеля: что реально доступно (RU / зарубежные / заблокированные сайты),
куда идут маршруты и DNS, что осталось от VPN-обходчиков (TUN/TAP-адаптеры, системный прокси, Winsock LSP, hosts).

Порт [netutil](original/) (@MrLargha) на C++ и [AUI](https://github.com/aui-framework/aui). Работает на Windows и Linux.

## Состав

- `core/` — библиотека `netanal_core`: сбор и разбор системных данных (`System`, `Parsers`), DNS и split-DNS
  (`Dns`), пробы сайтов/UDP/скорости (`Probes`, `Http`, `Socket`), онлайн-проверка и мониторинг (`Online`),
  вердикты (`Verdicts`), текстовый и JSON-отчёт (`Report`), списки сайтов (`Sites`).
  Платформенный код — в `core/src/platform/{win32,linux}`.
- `src/` — GUI `netanal`: главная (сводка, мониторинг туннеля, зоны, VPN, IP, DNS, система, UDP), «Сводка»,
  «Система», редактор списков, трей и уведомления. На Linux трей — StatusNotifierItem (KDE, XFCE, GNOME с
  расширением AppIndicator); если хоста трея нет, крестик закрывает программу.
- `cli/` — консольная `netanal_cli` (аналог `netutil.py --cli` / `--export`).
- `tests/` — тесты парсеров и вердиктов.

```
netanal_cli [--cli] [--export[=файл]] [--online]
```

Запускать от администратора (root на Linux): без прав недоступна часть данных (DNS-кэш, процессы, брандмауэр).

## Списки сайтов

По умолчанию по 25 доменов на зону. Кнопка «Списки» открывает редактор; списки сохраняются в `sites.json` рядом с
исполняемым файлом и читаются при старте.

## Сборка

```bash
cmake -B build -GNinja
cmake --build build --parallel 8
cmake --build build --target Tests && ./build/bin/Tests
```

AUI и зависимости (curl, mbedTLS) подтягивает AUI.Boot. Под Windows собирается MSVC или MinGW.

## Ресурсы

- Иконки — [Noto Emoji](https://github.com/googlefonts/noto-emoji) (Apache License 2.0), `assets/emoji/`.
- Шрифт — [Open Sans](https://github.com/googlefonts/opensans) (Apache License 2.0), `assets/font/`.
