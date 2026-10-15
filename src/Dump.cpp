#include "Dump.h"

#include "Architecture.h"
#include "Format.h"
#include "Options.h"
#include "Style.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

#include <iostream>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat, const Style& style)
{
    if (fat.size() == 1) {
        std::cout << "[*] " << style.bold() << "Mach-O, " << archName(*fat.at(0)) << style.reset() << '\n';

        return;
    }

    std::cout << "[*] " << style.bold() << "Universal binary with " << fat.size() << " slices:" << style.reset() << '\n';

    // FatBinary can be iterated as a container of Binaries, one per slice.
    for (const LIEF::MachO::Binary& binary : fat) {
        std::cout << "    - " << archName(binary) << " at file offset " << hex(binary.fat_offset()) << '\n';
    }
}

bool dumpSlice(const LIEF::MachO::Binary& binary, const Options& options, const Style& style)
{
    std::cout << '\n' << style.bold() << style.green() << "### " << archName(binary) << " ###" << style.reset() << '\n';

    if (options.getShowHeader()) {
        dumpHeader(binary, style);
    }

    if (options.getShowCommands()) {
        dumpCommands(binary, style);
    }

    if (options.getShowSegments()) {
        dumpSegments(binary, style);
    }

    if (options.getShowSections()) {
        dumpSections(binary, style);
    }

    if (options.getShowLibraries()) {
        dumpLibraries(binary, style);
    }

    bool succeeded = true;

    for (const std::string& sectionName : options.getHexdumps()) {
        if (!dumpHexdump(binary, sectionName, style)) {
            succeeded = false;
        }
    }

    return succeeded;
}

void printTitle(const Style& style, std::string_view title)
{
    std::cout << '\n' << style.bold() << style.purple() << "== " << title << " ==" << style.reset() << '\n';
}

} // namespace madamp

// EOF