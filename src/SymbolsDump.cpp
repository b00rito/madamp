#include "AddressMap.h"
#include "Dump.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>
#include <mach-o/nlist.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace madamp {

namespace {

constexpr auto weakReference = static_cast<std::uint16_t>(N_WEAK_REF);

// The library ordinal of an imported symbol. From its binding info when it
// has one, else from the high byte of its nlist n_desc, where 0xfe and
// 0xff stand for -2 and -1.
std::int32_t importOrdinal(const LIEF::MachO::Symbol& symbol)
{
    if (const LIEF::MachO::BindingInfo* binding = symbol.binding_info()) {
        return binding->library_ordinal();
    }

    return static_cast<std::int8_t>(symbol.description() >> 8);
}

// A weak import may be missing at run time. dyld binds it to 0 instead of
// refusing to launch.
bool isWeakImport(const LIEF::MachO::Symbol& symbol)
{
    const LIEF::MachO::BindingInfo* binding = symbol.binding_info();

    if (binding && binding->is_weak_import()) {
        return true;
    }

    return (symbol.description() & weakReference) != 0;
}

// "__DATA,__data" or "__TEXT" for an address, or "?" outside the image.
std::string placeOf(const AddressMap& map, std::uint64_t address)
{
    Location location = map.locate(address);

    if (!location.segment) {
        return "?";
    }

    if (!location.section) {
        return location.segment->name();
    }

    return location.section->segment_name() + "," + location.section->name();
}

void appendNote(std::string& notes, std::string_view note)
{
    if (!notes.empty()) {
        notes += ", ";
    }

    notes += note;
}

void printImportGroup(const LIEF::MachO::Binary& binary, std::int32_t ordinal, const std::vector<const LIEF::MachO::Symbol*>& symbols, const Style& style)
{
    if (ordinal > 0) {
        const LIEF::MachO::DylibCommand& library = *loadedLibraries(binary)[ordinal - 1];

        std::cout << "  " << style.bold() 
                  << "#" << ordinal 
                  << ' ' << library.name() << style.reset()
                  << ' ' << style.dim()
                  << "(" << to_string(library.command()) << ")" << style.reset()
                  << '\n';
    } else {
        std::cout << "  " << style.bold()
                  << "ordinal " << ordinal
                  << ' ' << ordinalName(binary, ordinal) << style.reset()
                  << '\n';
    }

    for (const LIEF::MachO::Symbol* symbol : symbols) {
        if (!isWeakImport(*symbol)) {
            std::cout << "       " << symbol->name() << '\n';

            continue;
        }

        std::cout << "       " << std::left << std::setw(31) << symbol->name()
                  << ' ' << style.yellow()
                  << "weak-import" << style.reset()
                  << '\n';
    }
}

void dumpImports(const LIEF::MachO::Binary& binary, const Style& style)
{
    printTitle(style, "Imports");

    std::map<std::int32_t, std::vector<const LIEF::MachO::Symbol*>> symbolsByOrdinal;

    for (const LIEF::MachO::Symbol& symbol : binary.imported_symbols()) {
        symbolsByOrdinal[importOrdinal(symbol)].push_back(&symbol);
    }

    if (symbolsByOrdinal.empty()) {
        std::cout << "  " << style.dim() << "(none)" << style.reset() << '\n';

        return;
    }

    // Libraries in load-command order, then the special ordinals.
    for (const auto& [ordinal, symbols] : symbolsByOrdinal) {
        if (ordinal > 0) {
            printImportGroup(binary, ordinal, symbols, style);
        }
    }

    for (const auto& [ordinal, symbols] : symbolsByOrdinal) {
        if (ordinal <= 0) {
            printImportGroup(binary, ordinal, symbols, style);
        }
    }
}

void printExport(std::string_view address, std::string_view name, std::string_view place, const std::string& notes, const Style& style)
{
    std::cout << "  " << std::left << std::setw(18) << address
              << ' ' << std::setw(32) << name << ' ';

    if (notes.empty()) {
        std::cout << place << '\n';

        return;
    }

    std::cout << std::setw(24) << place << ' ' << style.yellow() << notes << style.reset() << '\n';
}

// Binaries linked before LC_DYLD_EXPORTS_TRIE keep their exports in
// LC_DYLD_INFO, and LIEF lists them as exported symbols.
void dumpSymbolTableExports(const LIEF::MachO::Binary& binary, const AddressMap& map, const Style& style)
{
    for (const LIEF::MachO::Symbol& symbol : binary.exported_symbols()) {
        printExport(hex(symbol.value(), 16), symbol.name(), placeOf(map, symbol.value()), { }, style);
    }
}

void dumpExports(const LIEF::MachO::Binary& binary, const AddressMap& map, const Style& style)
{
    const LIEF::MachO::DyldExportsTrie* trie = binary.dyld_exports_trie();

    if (!trie) {
        printTitle(style, "Exports (symbol table)");
        dumpSymbolTableExports(binary, map, style);

        return;
    }

    printTitle(style, "Exports (LC_DYLD_EXPORTS_TRIE)");
    std::cout << style.dim() << "  " << std::left << std::setw(19)
                             << "address" << std::setw(33)
                             << "name" << std::setw(25)
                             << "where"
                             << "notes" << style.reset()
                             << '\n';

    for (const LIEF::MachO::ExportInfo& exported : trie->exports()) {
        std::string name = exported.has_symbol() ? exported.symbol()->name() : "?";
        std::string notes;

        if (exported.has(LIEF::MachO::ExportInfo::FLAGS::WEAK_DEFINITION)) {
            appendNote(notes, "weak-def");
        }

        if (exported.kind() == LIEF::MachO::ExportInfo::KIND::THREAD_LOCAL_KIND) {
            appendNote(notes, "thread-local");
        }

        // A re-export has no address here: the symbol lives in another
        // library, possibly under another name.
        if (exported.has(LIEF::MachO::ExportInfo::FLAGS::REEXPORT)) {
            std::string library = exported.alias_library() ? exported.alias_library()->name() : "?";
            std::string alias = exported.alias() ? exported.alias()->name() : name;

            appendNote(notes, "re-export of " + alias + " from " + library);
            printExport("-", name, "", notes, style);

            continue;
        }

        if (exported.kind() == LIEF::MachO::ExportInfo::KIND::ABSOLUTE_KIND) {
            appendNote(notes, "absolute value");
            printExport(hex(exported.address()), name, "", notes, style);

            continue;
        }

        // Trie addresses are offsets from the image base, not addresses.
        std::uint64_t address = binary.imagebase() + exported.address();

        if (exported.has(LIEF::MachO::ExportInfo::FLAGS::STUB_AND_RESOLVER)) {
            appendNote(notes, "resolver at " + hex(binary.imagebase() + exported.other()));
        }

        printExport(hex(address, 16), name, placeOf(map, address), notes, style);
    }
}

} // namespace

void dumpSymbols(const LIEF::MachO::Binary& binary, const AddressMap& map, const Style& style)
{
    dumpImports(binary, style);
    dumpExports(binary, map, style);
}

} // namespace madamp

// EOF
