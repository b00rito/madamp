#include "Dump.h"
#include "Format.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <iomanip>
#include <iostream>

namespace madamp {

void dumpLibraries(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Libraries");

    // libraries() includes a dylib's own name (LC_ID_DYLIB), so a dylib
    // lists itself first.
    for (const LIEF::MachO::DylibCommand& library : binary.libraries()) {
        std::cout << "  " << std::left
                          << std::setw(38)
                          << library.name()
                          << ' ' << style.dim()
                          << to_string(library.command())
                          << " (current " << versionString(library.current_version())
                          << ", compat " << versionString(library.compatibility_version())
                          << ")" << style.reset() << '\n';
    }

    for (const LIEF::MachO::RPathCommand& rpath : binary.rpaths()) {
        std::cout << "  " << style.yellow() << "rpath" << style.reset() << ' ' << rpath.path() << '\n';
    }
}

} // namespace madamp

// EOF