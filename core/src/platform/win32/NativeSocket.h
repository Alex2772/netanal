#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <AUI/Common/AString.h>

/// Winsock side of Socket.cpp.
namespace net::platform {

using NativeSocket = SOCKET;
inline constexpr NativeSocket NO_SOCKET = INVALID_SOCKET;

inline void ensureSocketsInit() {
    struct WinsockInit {
        WinsockInit() {
            WSADATA data;
            WSAStartup(MAKEWORD(2, 2), &data);
        }
        ~WinsockInit() { WSACleanup(); }
    };
    static WinsockInit init;
}

inline AString lastSocketError() {
    const int code = WSAGetLastError();
    switch (code) {
        case WSAECONNREFUSED:
            return "соединение отклонено";
        case WSAETIMEDOUT:
            return "таймаут";
        case WSAENETUNREACH:
            return "сеть недоступна";
        case WSAEHOSTUNREACH:
            return "узел недоступен";
        case WSAECONNRESET:
            return "соединение сброшено";
        default:
            return "ошибка сокета {}"_format(code);
    }
}

inline void setLastSocketError(int code) { WSASetLastError(code); }

/// Winsock reports getaddrinfo errors through WSAGetLastError.
inline AString resolveError(int) { return lastSocketError(); }

inline int pollOne(pollfd& fd, int timeoutMs) { return WSAPoll(&fd, 1, timeoutMs); }

inline void closeSocket(NativeSocket s) { closesocket(s); }

inline void setNonBlocking(NativeSocket s) {
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
}

inline bool connectInProgress() { return WSAGetLastError() == WSAEWOULDBLOCK; }

}   // namespace net::platform
