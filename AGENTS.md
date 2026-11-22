# AGENTS.md

Guidance for AI coding agents working on this AUI application (a consumer of the
[AUI Framework](https://github.com/aui-framework/aui)).

## Layout

- `original/` — the original Python program (`netutil.py`, `netutil_qt.py`) by @MrLargha. The C++ code is a port of
  it: keep texts, thresholds, colours and layout in sync with the original.
- `core/` — `netanal_core` static library (`aui_module`; system data, parsers, DNS, probes, verdicts, reports), shared
  by GUI, CLI and tests.
- `src/` — GUI sources, auto-globbed by `aui_executable`. Entry point is `AUI_ENTRY` (`<AUI/Platform/Entry.h>`).
  `widgets/` holds the declarative builders (`Widgets.h` includes them all), `main_window/` the parts of `MainWindow`
  (views, checks).
- `cli/` — `netanal_cli` console executable.
- `tests/` — GTest/GMock tests, enabled by `aui_enable_tests`.
- Platform code lives in `platform/win32/` and `platform/linux/` under `core/src`, `src` and `cli/src`. AUI drops
  the directories of other platforms from the glob; no `#ifdef _WIN32` in shared code. A shared header declares the
  API (`Platform.h`, `platform/Process.h`, `Tray.h`, `Console.h`); a header with per-platform contents (e.g.
  `NativeSocket.h`) lives in both platform directories and is picked by the `platform/<name>` include path.
- `assets/` — compiled into the binary by `aui_compile_assets`.
- `aui.boot.cmake` — AUI.Boot package manager; `AUI_VERSION` in `CMakeLists.txt` selects the AUI release.

Edit this project's files only. To read or change AUI itself, reconfigure with `-DAUIB_AUI_AS=TRUE`; AUI.Boot prints
where the editable sources are.

## Build and test

```bash
cmake -B build -GNinja
cmake --build build --parallel 8
cmake --build build --target Tests && ./build/bin/Tests
```

## Code style

4 spaces, max 120 columns, `mLikeThis` members, `lowerCamelCase` functions, `UPPER_SNAKE_CASE` constants, `A`-prefixed
public classes. Always put a trailing comma in UI DSL initializer lists:

```cpp
setContents(Vertical {
    Label { "Up" },
    Label { "Down" },   // <- trailing comma
});
```

Use `_new<T>(...)` / `_<T>`, signal-slot `connect(...)` and properties for data binding. Formatting follows
`.clang-format`. Keep comments and docs plain: no filler, no AI-flavoured prose.

## Looking at the running application

Verify UI changes in the real window with the `aui-remote` skill in `.claude/skills`. It locates `aui-remote` (needs an
AUI version that has `aui::dev_extras`), asks the user before adding a debug-only `ARemoteDebug::start` to the
application and then drives the app: inspect views, click, type, take screenshots.

> **Warning:** never link `aui::dev_extras` to release builds: the agent lets a client click, type and read the screen.
