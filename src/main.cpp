#include "Architecture.h"
#include "Dump.h"
#include "Error.h"
#include "ExitCode.h"
#include "Options.h"

#include <LIEF/MachO.hpp>
#include <LIEF/logging.hpp>

#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    const std::vector<std::string> arguments(argv + 1, argv + argc);
    std::optional<madamp::Options> options = madamp::Options::parse(arguments);

    if (!options) {
        madamp::printUsage(std::cerr);

        return madamp::toInt(madamp::ExitCode::UsageFailure);
    }

    if (options->getShowHelp()) {
        madamp::printUsage(std::cout);

        return madamp::toInt(madamp::ExitCode::Success);
    }

    if (options->getShowVersion()) {
        std::cout << "madamp " << madamp::version << '\n';

        return madamp::toInt(madamp::ExitCode::Success);
    }

    const std::string& path = options->getPath();

    // disable LIEF logging; use ours
    LIEF::logging::disable();

    std::error_code error;

    if (!std::filesystem::is_regular_file(path, error)) {
        return madamp::fail("no such file", path);
    }

    if (!LIEF::MachO::is_macho(path)) {
        return madamp::fail("not a Mach-O file", path);
    }

    std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(path);

    if (!fat || fat->empty()) {
        return madamp::fail("LIEF could not parse it", path);
    }

    madamp::printSlices(*fat);

    return madamp::toInt(madamp::ExitCode::Success);
}

// EOF