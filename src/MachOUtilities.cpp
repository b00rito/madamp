#include "MachOUtilities.h"

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

} // namespace madamp

// EOF