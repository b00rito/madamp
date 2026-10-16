#include "Dump.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace madamp {

namespace {

// Writable and executable at once is suspicious, so it's red.
std::string_view protectionColor(const Style& style, std::uint32_t protection)
{
    bool writable = protection & protectionWrite;
    bool executable = protection & protectionExecute;

    if (writable && executable) {
        return style.red();
    }

    if (executable) {
        return style.green();
    }

    if (writable) {
        return style.yellow();
    }

    return style.dim();
}

} // namespace

void dumpSegments(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Segments");
    std::cout << style.dim() << "  " << std::left << std::setw(17)
                             << "name" << std::setw(19)
                             << "vmaddr" << std::setw(13)
                             << "vmsize" << std::setw(13)
                             << "fileoff" << std::setw(13)
                             << "filesize" << std::setw(6)
                             << "init" << std::setw(6)
                             << "max"
                             << "nsect" << style.reset() << '\n';

    for (const LIEF::MachO::SegmentCommand& segment : binary.segments()) {
        std::uint32_t initial = segment.init_protection();

        std::cout << "  " << style.bold() << std::left
                          << std::setw(17)
                          << segment.name()
                          << style.reset()
                          << std::setw(19)
                          << hex(segment.virtual_address(), 16)
                          << std::setw(13)
                          << hex(segment.virtual_size())
                          << std::setw(13)
                          << hex(segment.file_offset())
                          << std::setw(13)
                          << hex(segment.file_size())
                          << protectionColor(style, initial)
                          << std::setw(6)
                          << protectionString(initial)
                          << style.reset()
                          << std::setw(6)
                          << protectionString(segment.max_protection())
                          << segment.numberof_sections();

        // vmsize > filesize: the loader fills the rest with zeros.
        if (segment.virtual_size() > segment.file_size() && segment.file_size() != 0) {
            std::cout << "  " << style.dim() << "(+" << hex(segment.virtual_size() - segment.file_size()) << " zero-fill)" << style.reset();
        }

        std::cout << '\n';
    }
}

} // namespace madamp

// EOF