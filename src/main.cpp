#include "Architecture.h"
#include "Dump.h"
#include "Error.h"
#include "ExitCode.h"
#include "Options.h"
#include "Style.h"

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

    // dot draws only the first graph it reads.
    if (options->getShowDependencyGraph() && fat->size() > 1 && options->getArch().empty()) {
        return madamp::fail("a universal binary: --dot needs --arch", path);
    }

    const madamp::Style style(options->getUseColor());

    if (!options->getShowDependencyGraph()) {
        madamp::printSlices(*fat, style);
    }

    bool matched = false;
    bool succeeded = true;

    for (const LIEF::MachO::Binary& binary : *fat) {
        if (!options->includesArch(madamp::archName(binary))) {
            continue;
        }

        matched = true;

        if (!madamp::dumpSlice(binary, *options, style)) {
            succeeded = false;
        }
    }

    if (!matched) {
        return madamp::fail("no slice matching --arch " + options->getArch(), path);
    }

    return madamp::toInt(succeeded ? madamp::ExitCode::Success : madamp::ExitCode::InputFailure);
}

// EOF