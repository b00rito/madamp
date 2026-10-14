#include "Dump.h"
#include "Format.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <cstddef>
#include <iomanip>
#include <iostream>

namespace madamp {

void dumpCommands(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Load commands");
    std::cout << style.dim() << "  " << std::left << std::setw(4) << "#" << std::setw(29) << "command" << std::setw(11) << "offset" << "size" << style.reset() << '\n';

    std::size_t index = 0;

    for (const LIEF::MachO::LoadCommand& command : binary.commands()) {
        std::cout << "  " << std::left << std::setw(4) << index++ << style.cyan() << std::setw(29) << to_string(command.command()) << style.reset() << std::setw(11) << hex(command.command_offset()) << command.size();

        if (const auto* segment = command.cast<LIEF::MachO::SegmentCommand>()) {
            std::cout << "  " << style.bold() << segment->name() << style.reset();
        } else if (const auto* library = command.cast<LIEF::MachO::DylibCommand>()) {
            std::cout << "  " << library->name();
        } else if (const auto* rpath = command.cast<LIEF::MachO::RPathCommand>()) {
            std::cout << "  " << rpath->path();
        }

        std::cout << '\n';
    }
}

} // namespace madamp

// EOF