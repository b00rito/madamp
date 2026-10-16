#include "AddressMap.h"
#include "Dump.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <iomanip>
#include <iostream>
#include <string_view>

namespace madamp {

namespace {

std::ostream& field(std::string_view label)
{
    return std::cout << "  " << std::left << std::setw(13) << label << ' ';
}

} // namespace

void dumpAddress(const LIEF::MachO::Binary& binary, const AddressMap& map, std::uint64_t address, const Style& style)
{
    printTitle(style, "Address " + hex(address));

    Location location = map.locate(address);

    if (!location.segment) {
        std::cout << "  [*] not inside any segment of this slice\n";

        return;
    }

    const LIEF::MachO::SegmentCommand& segment = *location.segment;
    std::uint64_t segmentEnd = segment.virtual_address() + segment.virtual_size();

    field("segment") << style.bold() << segment.name() << style.reset()
                     << ' ' << style.dim()
                     << "(" << hex(segment.virtual_address())
                     << "-" << hex(segmentEnd)
                     << ", " << protectionString(segment.init_protection())
                     << ")" << style.reset() << '\n';

    if (location.section) {
        field("section") << location.section->segment_name() << "," << location.section->name()
                         << " +" << hex(address - location.section->address())
                         << ' ' << style.dim()
                         << "(" << to_string(location.section->type()) << ")"
                         << style.reset() << '\n';
    } else {
        field("section") << style.dim() << "(none: segment padding or header area)" << style.reset() << '\n';
    }

    if (!location.symbol.empty()) {
        field("symbol") << location.symbol << '\n';
    }

    if (!location.import.empty()) {
        field("import") << style.yellow() << location.import << style.reset() << '\n';
    }

    if (!location.cstring.empty()) {
        field("string") << location.cstring << '\n';
    }

    if (location.sliceOffset) {
        field("slice offset") << hex(*location.sliceOffset) << '\n';
        field("file offset") << hex(binary.fat_offset() + *location.sliceOffset) << '\n';

        // On arm64, __bss often fits inside the padding at the end of
        // __DATA's last page, so it has a file offset after all.
        if (location.section && isZeroFill(*location.section)) {
            std::cout << "  " << style.dim() << std::setw(13) << "note" << " inside the segment's file bytes, but the section is zero-fill:\n"
                      << "  " << std::setw(13) << "" << " those bytes are page padding, not data the program defined" << style.reset() << '\n';
        }

        return;
    }

    if (!segment.file_size() && !segment.init_protection()) {
        field("file offset") << style.dim() << "(none: reserved address space with no access, so any access faults)" << style.reset() << '\n';

        return;
    }

    field("file offset") << style.dim() << "(none: past the segment's filesize, zero-filled by the loader)" << style.reset() << '\n';
}

} // namespace madamp

// EOF