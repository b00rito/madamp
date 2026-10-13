#include "Dump.h"

#include <LIEF/MachO.hpp>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    const std::vector<std::string> arguments(argv + 1, argv + argc);

    if (arguments.size() != 1) {
        std::cerr << "usage: madamp <mach-o file>\n";

        return 2;
    }

    const std::string& path = arguments.front();

    std::unique_ptr<LIEF::MachO::FatBinary> fat = LIEF::MachO::Parser::parse(path);

    if (!fat || fat->empty()) {
        std::cerr << "error: cannot parse '" << path << "'\n";

        return 1;
    }

    madamp::printSlices(*fat);

    return 0;
}

// EOF