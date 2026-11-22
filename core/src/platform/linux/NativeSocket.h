#pragma once

#include <cerrno>
#include <cstring>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <AUI/Common/AString.h>

/// BSD sockets side of Socket.cpp.
namespace net::platform {

using NativeSocket = int;
inline constexpr NativeSocket NO_SOCKET = -1;

inline void ensureSocketsInit() {}

inline AString lastSocketError() { return strerror(errno); }

inline void setLastSocketError(int code) { errno = code; }

inline AString resolveError(int code) { return gai_strerror(code); }

inline int pollOne(pollfd& fd, int timeoutMs) { return poll(&fd, 1, timeoutMs); }

inline void closeSocket(NativeSocket s) { close(s); }

inline void setNonBlocking(NativeSocket s) { fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK); }

inline bool connectInProgress() { return errno == EINPROGRESS; }

}   // namespace net::platform
