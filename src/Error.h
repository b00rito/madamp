#pragma once

#include <string_view>

namespace madamp {

void printError(std::string_view message);

[[nodiscard]] int fail(std::string_view message, std::string_view path);

} // namespace madamp

// EOF