#pragma once

namespace madamp {

enum class ExitCode : int {
    Success = 0,
    InputFailure = 1,
    UsageFailure = 2,
};

constexpr int toInt(ExitCode code)
{
    return static_cast<int>(code);
}

static_assert(toInt(ExitCode::Success) == 0);
static_assert(toInt(ExitCode::InputFailure) == 1);
static_assert(toInt(ExitCode::UsageFailure) == 2);

} // namespace madamp

// EOF