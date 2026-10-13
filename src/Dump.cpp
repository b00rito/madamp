#include "Dump.h"

#include "Architecture.h"
#include "Format.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

#include <iostream>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat)
{
    if (fat.size() == 1) {
        std::cout << "Mach-O, " << archName(*fat.at(0)) << '\n';

        return;
    }

    std::cout << "Universal binary with " << fat.size() << " slices:\n";

    // FatBinary can be iterated as a container of Binaries, one per slice.
    for (const LIEF::MachO::Binary& binary : fat) {
        std::cout << "  - " << archName(binary) << " at file offset " << hex(binary.fat_offset()) << '\n';
    }
}

} // namespace madamp

// EOF