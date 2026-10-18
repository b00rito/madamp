#include "MachOUtilities.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/LoadCommand.hpp>
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

std::vector<const LIEF::MachO::DylibCommand*> loadedLibraries(const LIEF::MachO::Binary& binary)
{
    std::vector<const LIEF::MachO::DylibCommand*> libraries;

    for (const LIEF::MachO::LoadCommand& command : binary.commands()) {
        switch (command.command()) {
        case LIEF::MachO::LoadCommand::TYPE::LOAD_DYLIB:
        case LIEF::MachO::LoadCommand::TYPE::LOAD_WEAK_DYLIB:
        case LIEF::MachO::LoadCommand::TYPE::REEXPORT_DYLIB:
        case LIEF::MachO::LoadCommand::TYPE::LAZY_LOAD_DYLIB:
        case LIEF::MachO::LoadCommand::TYPE::LOAD_UPWARD_DYLIB:
            libraries.push_back(command.cast<LIEF::MachO::DylibCommand>());
            break;
        default:
            break;
        }
    }

    return libraries;
}

std::string ordinalName(const LIEF::MachO::Binary& binary, std::int32_t ordinal)
{
    switch (ordinal) {
    case ordinalSelf:
        return "(this image)";
    case ordinalMainExecutable:
        return "(main executable)";
    case ordinalFlatLookup:
        return "(flat lookup: first image that defines it)";
    case ordinalWeakLookup:
        return "(weak lookup: one definition shared by all images)";
    default:
        break;
    }

    std::vector<const LIEF::MachO::DylibCommand*> libraries = loadedLibraries(binary);

    if (ordinal < 1 || static_cast<std::size_t>(ordinal) > libraries.size()) {
        return "(bad ordinal " + std::to_string(ordinal) + ")";
    }

    return libraries[ordinal - 1]->name();
}

} // namespace madamp

// EOF