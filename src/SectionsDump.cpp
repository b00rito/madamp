#include "Dump.h"
#include "Format.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <iomanip>
#include <iostream>
#include <string>

namespace madamp {

void dumpSections(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Sections");
    std::cout << style.dim() << "  " << std::left << std::setw(35)
                             << "segment,section" << std::setw(19)
                             << "address" << std::setw(11)
                             << "size" << std::setw(11)
                             << "offset" << std::setw(7)
                             << "align"
                             << "type" << style.reset() << '\n';

    for (const LIEF::MachO::Section& section : binary.sections()) {
        std::string name = section.segment_name() + "," + section.name();

        // The alignment is stored as a power of two.
        std::string alignment = "2^" + std::to_string(section.alignment());

        std::cout << "  " << std::left
                          << std::setw(35)
                          << name
                          << std::setw(19)
                          << hex(section.address(), 16)
                          << std::setw(11)
                          << hex(section.size())
                          << std::setw(11)
                          << hex(section.offset())
                          << std::setw(7)
                          << alignment
                          << style.cyan()
                          << to_string(section.type())
                          << style.reset() << '\n';
    }
}

} // namespace madamp

// EOF