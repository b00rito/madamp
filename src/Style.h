#pragma once

#include <string_view>

namespace madamp {

class Style {
public:
    explicit Style(bool enabled)
        : m_enabled(enabled)
    {
    }

    std::string_view bold() const { return code("\x1b[1m"); }
    std::string_view green() const { return code("\x1b[32m"); }
    std::string_view purple() const { return code("\x1b[34m"); }
    std::string_view cyan() const { return code("\x1b[36m"); }
    std::string_view dim() const { return code("\x1b[2m"); }
    std::string_view reset() const { return code("\x1b[0m"); }

private:
    std::string_view code(std::string_view escape) const
    {
        if (!m_enabled) {
            return {};
        }

        return escape;
    }

    bool m_enabled;
};

} // namespace madamp

// EOF