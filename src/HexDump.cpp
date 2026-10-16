#include "Architecture.h"
#include "Dump.h"
#include "Error.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>

namespace madamp {

namespace {

// A section named "SEG,SECT", or just "SECT" (the first one with that
// name). nullptr if there's none.
const LIEF::MachO::Section* findSection(const LIEF::MachO::Binary& binary, const std::string& name)
{
    std::size_t comma = name.find(',');

    if (comma == std::string::npos) {
        return binary.get_section(name);
    }

    return binary.get_section(name.substr(0, comma), name.substr(comma + 1));
}

std::string byteHex(std::uint8_t byte)
{
    constexpr std::string_view digits = "0123456789abcdef";

    return { digits[byte >> 4], digits[byte & 0xf] };
}

} // namespace

// An xxd-style dump, addressed by VM address so it lines up with
// disassemblers.
bool dumpHexdump(const LIEF::MachO::Binary& binary, const std::string& sectionName, const Style& style)
{
    const LIEF::MachO::Section* section = findSection(binary, sectionName);

    if (!section) {
        printError("no section '" + sectionName + "' in the " + std::string(archName(binary)) + " slice");

        return false;
    }

    printTitle(style, "Hexdump " + section->segment_name() + "," + section->name());

    if (isZeroFill(*section)) {
        std::cout << "  [*] " << style.dim()
                              << hex(section->size())
                              << " bytes of zero-fill: no file content, the loader maps zeroed pages"
                              << style.reset() << '\n';

        return true;
    }

    // Section offsets are relative to the slice. Add the slice's offset
    // in the fat file to get the position in the file itself.
    std::cout << "  " << style.dim()
                      << "address " << hex(section->address())
                      << ", size " << hex(section->size())
                      << ", slice offset " << hex(section->offset())
                      << ", file offset " << hex(binary.fat_offset() + section->offset())
                      << style.reset() << '\n';

    LIEF::span<const std::uint8_t> bytes = section->content();
    constexpr std::size_t bytesPerLine = 16;

    for (std::size_t line = 0; line < bytes.size(); line += bytesPerLine) {
        std::string text;

        std::cout << "  " << style.cyan() << hex(section->address() + line, 16).substr(2) << style.reset() << "  ";

        for (std::size_t i = 0; i < bytesPerLine; ++i) {
            if (line + i < bytes.size()) {
                std::uint8_t byte = bytes[line + i];
                bool printable = byte >= 0x20 && byte < 0x7f;

                std::cout << byteHex(byte);
                text += printable ? static_cast<char>(byte) : '.';
            } else {
                std::cout << "  ";
            }

            std::cout << (i == 7 ? "  " : " ");
        }

        std::cout << " |" << text << "|\n";
    }

    return true;
}

} // namespace madamp

// EOF