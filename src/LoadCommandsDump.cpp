#include "Dump.h"
#include "Format.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <string>

namespace madamp {

void dumpCommands(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Load commands");
    std::cout << style.dim() << "  " << std::left << std::setw(4)
                             << "#" << std::setw(29)
                             << "command" << std::setw(11)
                             << "offset" << std::setw(8)
                             << "size"
                             << "name" << style.reset() << '\n';

    std::size_t index = 0;

    for (const LIEF::MachO::LoadCommand& command : binary.commands()) {
        std::string name;
        bool isSegment = false;

        if (const auto* segment = command.cast<LIEF::MachO::SegmentCommand>()) {
            name = segment->name();
            isSegment = true;
        } else if (const auto* library = command.cast<LIEF::MachO::DylibCommand>()) {
            name = library->name();
        } else if (const auto* rpath = command.cast<LIEF::MachO::RPathCommand>()) {
            name = rpath->path();
        }

        std::cout << "  " << std::left
                          << std::setw(4)
                          << index++
                          << style.cyan()
                          << std::setw(29)
                          << to_string(command.command())
                          << style.reset()
                          << std::setw(11)
                          << hex(command.command_offset());

        // No padding after the size when there's no name to line up.
        if (name.empty()) {
            std::cout << hex(command.size()) << '\n';

            continue;
        }

        std::cout << std::setw(8)
                  << hex(command.size())
                  << (isSegment ? style.bold() : "")
                  << name
                  << (isSegment ? style.reset() : "") << '\n';
    }
}

} // namespace madamp

// EOF