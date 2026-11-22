#pragma once

#include <utility>
#include <variant>

namespace net {

template <typename... Fs>
struct Overloaded : Fs... {
    using Fs::operator()...;
};

/// Exhaustive std::visit: a forgotten alternative is a compile error.
template <typename V, typename... Fs>
constexpr decltype(auto) match(V&& variant, Fs&&... fs) {
    return std::visit(Overloaded<std::decay_t<Fs>...> { std::forward<Fs>(fs)... }, std::forward<V>(variant));
}

}   // namespace net
