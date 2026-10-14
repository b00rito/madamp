#include "ExitCode.h"

#include <iostream>
#include <string>

namespace madamp {

void printError(std::string_view message)
{
    std::cerr << "[-] madamp: error: " << message << '\n';
}

int fail(std::string_view message, std::string_view path)
{
    printError("'" + std::string(path) + "': " + std::string(message));

    return toInt(ExitCode::InputFailure);
}

} // namespace madamp

// EOF