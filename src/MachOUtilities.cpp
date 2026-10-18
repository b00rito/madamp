#include "MachOUtilities.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/Section.hpp>

namespace madamp {

std::string protectionString(std::uint32_t protection)
{
    std::string text = "---";

    if (protection & protectionRead) {
        text[0] = 'r';
    }

    if (protection & protectionWrite) {
        text[1] = 'w';
    }

    if (protection & protectionExecute) {
        text[2] = 'x';
    }

    return text;
}

bool isZeroFill(const LIEF::MachO::Section& section)
{
    switch (section.type()) {
    case LIEF::MachO::Section::TYPE::ZEROFILL:
    case LIEF::MachO::Section::TYPE::GB_ZEROFILL:
    case LIEF::MachO::Section::TYPE::THREAD_LOCAL_ZEROFILL:
        return true;
    default:
        return false;
    }
}

const LIEF::MachO::Section* findSection(const LIEF::MachO::Binary& binary, const std::string& name)
{
    std::size_t comma = name.find(',');

    if (comma == std::string::npos) {
        return binary.get_section(name);
    }

    return binary.get_section(name.substr(0, comma), name.substr(comma + 1));
}

} // namespace madamp

// EOF