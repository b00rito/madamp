#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace madamp {

// "0x" and lowercase hex digits; at zero-padded width
// hex(0x20, 4) is "0x0020".
std::string hex(std::uint64_t value, std::size_t width = 0);

// "14.0.0" from {14, 0, 0}.
template<typename Version>
std::string versionString(const Version& version)
{
    std::string text;

    for (auto part : version) {
        if (!text.empty()) {
            text += '.';
        }

        text += std::to_string(part);
    }

    return text;
}

} // namespace madamp

// EOF