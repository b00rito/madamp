#pragma once

#include <cstdint>
#include <string>

namespace madamp {

// "0x" and lowercase hex digits; at zero-padded width
// hex(0x20, 4) is "0x0020".
std::string hex(std::uint64_t value);

} // namespace madamp

// EOF