#pragma once

#include <string_view>

namespace madamp {

// What main() returns. An enum class doesn't convert to int on its own,
// so the conversion is spelled out with static_cast.
enum class ExitCode : int {
    Success = 0,
    InputFailure = 1, // the input couldn't be read or parsed
    UsageFailure = 2, // the command line was wrong
};

constexpr int toInt(ExitCode code) { return static_cast<int>(code); }

static_assert(toInt(ExitCode::Success) == 0);
static_assert(toInt(ExitCode::InputFailure) == 1);
static_assert(toInt(ExitCode::UsageFailure) == 2);

void printError(std::string_view message);

[[nodiscard]] int fail(std::string_view message, std::string_view path);

} // namespace madamp

// EOF