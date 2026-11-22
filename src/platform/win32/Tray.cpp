#include "Tray.h"

#include <span>

#include <windows.h>
#include <shellapi.h>

#include "Theme.h"
#include "TrayIcon.h"

namespace {

constexpr UINT WM_TRAY = WM_APP + 1;
constexpr UINT ID_OPEN = 1;
constexpr UINT ID_QUIT = 2;
constexpr auto CLASS_NAME = L"NetAnalTray";

std::wstring wide(const AString& s) {
    const auto utf8 = s.toStdString();
    const int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), out.data(), n);
    return out;
}

template <size_t N>
void copyTo(wchar_t (&dst)[N], const AString& s) {
    const auto w = wide(s);
    wcsncpy_s(dst, N, w.c_str(), _TRUNCATE);
}

/// The status circle as an icon.
HICON circleIcon(AColor color) {
    constexpr int SIZE = tray_icon::SIZE;
    BITMAPV5HEADER bi {};
    bi.bV5Size = sizeof(bi);
    bi.bV5Width = SIZE;
    bi.bV5Height = -SIZE;
    bi.bV5Planes = 1;
    bi.bV5BitCount = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask = 0x00ff0000;
    bi.bV5GreenMask = 0x0000ff00;
    bi.bV5BlueMask = 0x000000ff;
    bi.bV5AlphaMask = 0xff000000;
    void* bits = nullptr;
    const auto dc = GetDC(nullptr);
    const auto color32 = CreateDIBSection(dc, reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, dc);
    const auto pixels = std::span(static_cast<uint32_t*>(bits), SIZE * SIZE);
    for (int y = 0; y < SIZE; ++y) {
        for (int x = 0; x < SIZE; ++x) {
            const float a = tray_icon::coverage(x, y);
            const auto premul = [&](float c) { return uint32_t(c * a * 255.f + 0.5f); };
            pixels[y * SIZE + x] = (uint32_t(a * 255.f + 0.5f) << 24) | (premul(color.r) << 16) |
                                   (premul(color.g) << 8) | premul(color.b);
        }
    }
    const auto mask = CreateBitmap(SIZE, SIZE, 1, 1, nullptr);
    ICONINFO info { .fIcon = TRUE, .hbmMask = mask, .hbmColor = color32 };
    const auto icon = CreateIconIndirect(&info);
    DeleteObject(mask);
    DeleteObject(color32);
    return icon;
}

}   // namespace

struct Tray::Impl {
    Actions actions;
    HWND window = nullptr;
    NOTIFYICONDATAW data {};
    HICON icon = nullptr;

    static LRESULT CALLBACK proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        auto self = reinterpret_cast<Impl*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (!self || msg != WM_TRAY) {
            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }
        switch (LOWORD(lParam)) {
            case WM_LBUTTONDBLCLK:
            case NIN_BALLOONUSERCLICK:
                self->actions.onOpen();
                break;
            case WM_RBUTTONUP:
            case WM_CONTEXTMENU:
                self->menu();
                break;
        }
        return 0;
    }

    void menu() {
        const auto m = CreatePopupMenu();
        AppendMenuW(m, MF_STRING, ID_OPEN, wide("Открыть NetAnal").c_str());
        AppendMenuW(m, MF_STRING, ID_QUIT, wide("Выйти").c_str());
        POINT pt;
        GetCursorPos(&pt);
        SetForegroundWindow(window);
        const auto cmd = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pt.x, pt.y, 0, window,
                                        nullptr);
        DestroyMenu(m);
        if (cmd == ID_OPEN) {
            actions.onOpen();
        } else if (cmd == ID_QUIT) {
            actions.onQuit();
        }
    }
};

Tray::Tray(Actions actions) : mImpl(std::make_unique<Impl>()) {
    mImpl->actions = std::move(actions);
    WNDCLASSW wc { .lpfnWndProc = Impl::proc, .hInstance = GetModuleHandleW(nullptr), .lpszClassName = CLASS_NAME };
    RegisterClassW(&wc);
    mImpl->window = CreateWindowW(CLASS_NAME, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
    SetWindowLongPtrW(mImpl->window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(mImpl.get()));

    auto& d = mImpl->data;
    d.cbSize = sizeof(d);
    d.hWnd = mImpl->window;
    d.uID = 1;
    d.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    d.uCallbackMessage = WM_TRAY;
    mImpl->icon = circleIcon(theme::MONITOR_OFF);
    d.hIcon = mImpl->icon;
    copyTo(d.szTip, "NetAnal");
    Shell_NotifyIconW(NIM_ADD, &d);
}

Tray::~Tray() {
    Shell_NotifyIconW(NIM_DELETE, &mImpl->data);
    DestroyIcon(mImpl->icon);
    DestroyWindow(mImpl->window);
}

bool Tray::hasIcon() const { return true; }

void Tray::setColor(AColor color) {
    const auto old = std::exchange(mImpl->icon, circleIcon(color));
    mImpl->data.uFlags = NIF_ICON;
    mImpl->data.hIcon = mImpl->icon;
    Shell_NotifyIconW(NIM_MODIFY, &mImpl->data);
    DestroyIcon(old);
}

void Tray::setToolTip(const AString& value) {
    mImpl->data.uFlags = NIF_TIP;
    copyTo(mImpl->data.szTip, value);
    Shell_NotifyIconW(NIM_MODIFY, &mImpl->data);
}

void Tray::showMessage(const AString& title, const AString& message, Kind kind) {
    auto& d = mImpl->data;
    d.uFlags = NIF_INFO;
    d.dwInfoFlags = kind == Kind::WARNING ? NIIF_WARNING : NIIF_INFO;
    copyTo(d.szInfoTitle, title);
    copyTo(d.szInfo, message);
    Shell_NotifyIconW(NIM_MODIFY, &d);
}
