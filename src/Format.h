#pragma once

#include <cstdint>
#include <string>

namespace madamp {

// Formats a number as "0x" followed by lowercase hex digits.
std::string hex(std::uint64_t value);

} // namespace madamp

// EOF