#include "Format.h"

#include <array>
#include <charconv>

namespace madamp {

// std::to_chars (C++17) writes the digits into a buffer we provide and
// returns where it stopped; 16 hex digits fit any 64-bit value.
std::string
hex(std::uint64_t value)
{
    std::array<char, 16> digits {};
    auto result = std::to_chars(digits.data(), digits.data() + digits.size(), value, 16);

    return "0x" + std::string(digits.data(), result.ptr);
}

} // namespace madamp

// EOF