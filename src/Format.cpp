#include "Format.h"

#include <array>
#include <charconv>
#include <string_view>

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

std::string byteHex(std::uint8_t byte)
{
    constexpr std::string_view digits = "0123456789abcdef";

    return { digits[byte >> 4], digits[byte & 0xf] };
}

} // namespace madamp

// EOF