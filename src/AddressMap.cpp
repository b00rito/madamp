#include "AddressMap.h"

#include "Format.h"

#include <LIEF/MachO.hpp>

#include <vector>

namespace madamp {

namespace {

// Debug builds carry STABS "debug map" entries (N_BNSYM, N_FUN, N_SO,
// ...) that dsymutil uses to find the .o files. Symbol::type() masks
// off the N_STAB bits, so some of them look like ordinary N_SECT
// symbols with empty names; the raw type tells them apart.
constexpr std::uint8_t stabMask = 0xe0; // N_STAB in <mach-o/nlist.h>

std::string quote(const std::string& text)
{
    constexpr std::size_t maximumLength = 48;
    std::string quoted = "\"";

    for (std::size_t i = 0; i < text.size() && i < maximumLength; ++i) {
        char c = text[i];

        if (c == '\n') {
            quoted += "\\n";
        } else if (c == '\t') {
            quoted += "\\t";
        } else if (c == '"') {
            quoted += "\\\"";
        } else {
            quoted += c;
        }
    }

    if (text.size() > maximumLength) {
        quoted += "...";
    }

    return quoted + "\"";
}

} // namespace

AddressMap::AddressMap(const LIEF::MachO::Binary& binary)
    : m_binary(binary)
{
    for (const LIEF::MachO::Symbol& symbol : binary.symbols()) {
        if (symbol.raw_type() & stabMask) {
            continue;
        }

        // Only symbols defined in this image (N_SECT) have an address.
        if (symbol.type() != LIEF::MachO::Symbol::TYPE::SECTION || !symbol.value() || symbol.name().empty()) {
            continue;
        }

        m_symbols.emplace(symbol.value(), symbol.name());
    }

    // Stub and pointer sections don't name their entries. Instead, the
    // section's reserved1 field is an index into the indirect symbol
    // table (LC_DYSYMTAB), and entry i of the section belongs to
    // indirect symbol reserved1 + i.
    const LIEF::MachO::DynamicSymbolCommand* dynamicSymbols = binary.dynamic_symbol_command();

    if (!dynamicSymbols) {
        return;
    }

    std::vector<const LIEF::MachO::Symbol*> indirect;

    for (const LIEF::MachO::Symbol& symbol : dynamicSymbols->indirect_symbols()) {
        indirect.push_back(&symbol);
    }

    for (const LIEF::MachO::Section& section : binary.sections()) {
        std::uint64_t entrySize = 0;
        std::string kind;

        if (section.type() == LIEF::MachO::Section::TYPE::SYMBOL_STUBS) {
            entrySize = section.reserved2(); // the size of one stub
            kind = section.name() == "__auth_stubs" ? "auth stub" : "stub";
        } else if (section.type() == LIEF::MachO::Section::TYPE::NON_LAZY_SYMBOL_POINTERS || section.type() == LIEF::MachO::Section::TYPE::LAZY_SYMBOL_POINTERS) {
            entrySize = 8; // one 64-bit pointer per slot

            // arm64e signs the pointers in __auth_got with PAC
            if (section.name() == "__got") {
                kind = "GOT";
            } else if (section.name() == "__auth_got") {
                kind = "auth GOT";
            } else {
                kind = "pointer";
            }
        }

        if (!entrySize) {
            continue;
        }

        for (std::uint64_t i = 0; i < section.size() / entrySize; ++i) {
            std::size_t index = section.reserved1() + i;

            if (index >= indirect.size()) {
                break;
            }

            m_imports.emplace(section.address() + i * entrySize, indirect[index]->name() + " (" + kind + ")");
        }
    }
}

Location AddressMap::locate(std::uint64_t address) const
{
    Location location;

    location.segment = m_binary.segment_from_virtual_address(address);

    if (!location.segment) {
        return location;
    }

    // Only the first filesize bytes of a segment come from the file; the
    // rest of vmsize is zero-filled by the loader.
    std::uint64_t delta = address - location.segment->virtual_address();

    if (delta < location.segment->file_size()) {
        location.sliceOffset = location.segment->file_offset() + delta;
    }

    location.section = m_binary.section_from_virtual_address(address);

    if (auto found = m_imports.find(address); found != m_imports.end()) {
        location.import = found->second;
    }

    // The nearest symbol at or before the address, as long as it's in
    // the same section.
    auto next = m_symbols.upper_bound(address);

    if (next != m_symbols.begin() && location.section) {
        auto symbol = std::prev(next);

        if (symbol->first >= location.section->address()) {
            location.symbol = symbol->second;

            if (symbol->first != address) {
                location.symbol += "+" + hex(address - symbol->first);
            }
        }
    }

    if (location.section && location.section->type() == LIEF::MachO::Section::TYPE::CSTRING_LITERALS) {
        LIEF::span<const std::uint8_t> bytes = location.section->content();
        std::string text;

        for (std::uint64_t i = address - location.section->address(); i < bytes.size() && bytes[i]; ++i) {
            text += static_cast<char>(bytes[i]);
        }

        location.cstring = quote(text);
    }

    return location;
}

} // namespace madamp

// EOF