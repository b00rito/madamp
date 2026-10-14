#include "Format.h"

#include <array>
#include <charconv>

namespace madamp {

// 16 hex digits fit any 64-bit value.
std::string hex(std::uint64_t value, std::size_t width)
{
    std::array<char, 16> digits {};
    auto result = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16);
    std::string text(digits.data(), result.ptr);

    if (text.size() < width) {
        text.insert(0, width - text.size(), '0');
    }

    return "0x" + text;
}

} // namespace madamp

// EOF