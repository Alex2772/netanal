#pragma once

#include <functional>

#include <AUI/Common/AProperty.h>
#include <AUI/Util/Declarative/Containers.h>
#include <AUI/Util/Declarative/Contracts.h>
#include <AUI/Util/UIBuildingHelpers.h>
#include <AUI/View/AViewContainer.h>

template <typename T>
using In = declarative::contract::In<T>;

/// Rebuilds its contents from `view` whenever `value` changes.
template <typename T>
struct Dynamic {
    In<T> value;
    std::function<_<AView>(const T&)> view;

    _<AView> operator()();
};

/// Moves a contract into a property that a builder can read in several AUI_REACT expressions. `owner` keeps the
/// binding alive.
template <typename T>
_<AProperty<T>> share(In<T> in, const _<AView>& owner) {
    auto property = _new<AProperty<T>>();
    in.bindTo(ASlotDef { owner.get(), [property](const T& value) { *property = value; } });
    return property;
}

/// Calls `view->*setter(value)` (or `setter(*view, value)`) with the current value of `in` and every change of it.
template <typename T, typename View, typename Setter>
void bindSetter(In<T>& in, const _<View>& view, Setter setter) {
    if constexpr (std::is_member_function_pointer_v<Setter>) {
        in.bindTo(ASlotDef { view.get(), setter });
    } else {
        // the connection belongs to the view, so it never outlives it
        in.bindTo(ASlotDef { view.get(), [&target = *view, setter = std::move(setter)](const T& value) {
            setter(target, value);
        } });
    }
}

/// Custom style of `view` built by `style(value)` from the current value of `in` and every change of it.
template <typename T, typename Style>
void bindStyle(In<T>& in, const _<AView>& view, Style style) {
    bindSetter(in, view, [style = std::move(style)](AView& target, const T& value) {
        target.setCustomStyle(style(value));
    });
}

namespace detail {

template <typename T>
class DynamicView : public AViewContainer {
public:
    explicit DynamicView(std::function<_<AView>(const T&)> view) : mView(std::move(view)) {
        setLayout(std::make_unique<AVerticalLayout>());
    }

    void show(const T& value) {
        removeAllViews();
        addView(mView(value));
    }

private:
    std::function<_<AView>(const T&)> mView;
};

}   // namespace detail

template <typename T>
_<AView> Dynamic<T>::operator()() {
    return aui::ui_building::view<detail::DynamicView<T>> { std::move(view) } AUI_LET {
        bindSetter(value, it, &detail::DynamicView<T>::show);
    };
}
