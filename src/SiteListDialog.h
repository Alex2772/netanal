#pragma once

#include <AUI/Platform/AWindow.h>
#include <AUI/Thread/AFuture.h>
#include <AUI/View/ATextArea.h>

#include "Sites.h"

/// Domain lists per zone, one URL per line.
class SiteListDialog : public AWindow {
public:
    using Result = AFuture<AOptional<net::SiteLists>>;

    /// Shows the dialog; the future gets the edited lists, or nothing when the dialog is cancelled.
    static Result ask(AWindow& parent, const net::SiteLists& current);

    SiteListDialog(AWindow& parent, const net::SiteLists& current, Result::Resolver resolver);
    ~SiteListDialog() override;

private:
    net::PerZone<_<ATextArea>> mEditors;
    Result::Resolver mResolver;

    void reset();
    [[nodiscard]] net::SiteLists values() const;
};
