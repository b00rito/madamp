#include "AddressMap.h"
#include "ChainedFixups.h"
#include "Dump.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>
#include <mach-o/fixup-chains.h>
#include <mach-o/loader.h>

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace madamp {

namespace {

constexpr auto pageStartNone = static_cast<std::uint16_t>(DYLD_CHAINED_PTR_START_NONE);

constexpr auto bindOpcodeMask = static_cast<std::uint8_t>(BIND_OPCODE_MASK);
constexpr auto bindSetDylibOrdinalUleb = static_cast<std::uint8_t>(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
constexpr auto bindSetSymbolTrailingFlagsImm = static_cast<std::uint8_t>(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
constexpr auto bindSetAddendSleb = static_cast<std::uint8_t>(BIND_OPCODE_SET_ADDEND_SLEB);
constexpr auto bindSetSegmentAndOffsetUleb = static_cast<std::uint8_t>(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB);
constexpr auto bindAddAddrUleb = static_cast<std::uint8_t>(BIND_OPCODE_ADD_ADDR_ULEB);
constexpr auto bindDoBindAddAddrUleb = static_cast<std::uint8_t>(BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB);
constexpr auto bindDoBindUlebTimesSkippingUleb = static_cast<std::uint8_t>(BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB);
constexpr auto bindThreaded = static_cast<std::uint8_t>(BIND_OPCODE_THREADED);

std::string_view strideNote(LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format)
{
    switch (format) {
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_64:
        return "stride 4, target is a vmaddr";
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
        return "stride 4, target is an offset from the image base";
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
        return "stride 8, target is a vmaddr, PAC";
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
        return "stride 8, target is an offset, PAC";
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
        return "stride 8, target is an offset, PAC, 24-bit import ordinals";
    default:
        return "not decoded by madamp";
    }
}

void skipLeb128(LIEF::span<const std::uint8_t> bytes, std::size_t& i)
{
    while (i < bytes.size() && (bytes[i++] & 0x80)) { }
}

// arm64e binaries linked before chained fixups use "threaded" binds. The
// bind opcodes only build an ordinal table and say "apply" and the ptrs
// are chained on disk in the PTR_ARM64E format.
bool usesThreadedBinds(const LIEF::MachO::Binary& binary)
{
    const LIEF::MachO::DyldInfo* info = binary.dyld_info();

    if (!info) {
        return false;
    }

    LIEF::span<const std::uint8_t> opcodes = info->bind_opcodes();

    for (std::size_t i = 0; i < opcodes.size();) {
        std::uint8_t opcode = opcodes[i++] & bindOpcodeMask;

        // Other opcodes carry only their 4-bit immediate.
        if (opcode == bindThreaded) {
            return true;
        }

        if (opcode == bindSetDylibOrdinalUleb || opcode == bindSetAddendSleb || opcode == bindSetSegmentAndOffsetUleb || opcode == bindAddAddrUleb || opcode == bindDoBindAddAddrUleb) {
            skipLeb128(opcodes, i);
        } else if (opcode == bindDoBindUlebTimesSkippingUleb) {
            skipLeb128(opcodes, i);
            skipLeb128(opcodes, i);
        } else if (opcode == bindSetSymbolTrailingFlagsImm) {
            while (i < opcodes.size() && opcodes[i++]) { }
        }
    }

    return false;
}

struct FixupRow {
    std::uint64_t address { 0 };
    std::uint64_t raw { 0 };
    bool bind { false };
    std::string next;
    std::string decoded;
    std::string resolved;
    std::string mismatch;
};

void printFixupColumns(std::string_view decodedLabel, const Style& style)
{
    std::cout << style.dim() << "    " << std::left << std::setw(18)
                             << "address" << ' ' << std::setw(18)
                             << "on disk" << ' ' << std::setw(6)
                             << "kind" << ' ' << std::setw(5)
                             << "next" << ' ' << std::setw(26)
                             << decodedLabel << ' '
                             << "resolves to" << style.reset() << '\n';
}

void printFixup(const FixupRow& row, const AddressMap& map, const Style& style)
{
    std::cout << "    " << hex(row.address, 16) << ' '
                        << hex(row.raw, 16).substr(2) << "   "
                        << (row.bind ? style.yellow() : style.cyan())
                        << std::left << std::setw(6)
                        << (row.bind ? "bind" : "rebase")
                        << style.reset() << ' '
                        << std::setw(5) << row.next << ' '
                        << std::setw(26) << row.decoded << ' '
                        << row.resolved << "  "
                        << style.dim() << "@ " << map.describe(row.address) << style.reset();

    if (!row.mismatch.empty()) {
        std::cout << "  " << style.red() << "!! " << row.mismatch << style.reset();
    }

    std::cout << '\n';
}

std::string bindTarget(const LIEF::MachO::Binary& binary, std::string_view name, std::int32_t ordinal)
{
    return std::string(name) + "  " + ordinalName(binary, ordinal);
}

// Binaries linked before chained fixups. LC_DYLD_INFO's rebase and bind
// opcodes. LIEF runs them and reports the rebases as DYLDINFO relocations.
void dumpDyldInfoFixups(const LIEF::MachO::Binary& binary, const AddressMap& map, const Style& style)
{
    bool threaded = usesThreadedBinds(binary);

    if (threaded) {
        std::cout << "  " << style.dim() << "LC_DYLD_INFO with threaded binds (arm64e, before chained fixups): the bind opcodes only\n"
                  << "  build an ordinal table; the pointers on disk are chained, in the DYLD_CHAINED_PTR_ARM64E format." << style.reset() << '\n';
    } else {
        std::cout << "  " << style.dim() << "LC_DYLD_INFO bind/rebase opcodes: small programs in __LINKEDIT that produce the list of\n"
                  << "  locations to fix up. The pointers on disk are plain, unslid values." << style.reset() << '\n';
    }

    // nullptr for a rebase.
    std::map<std::uint64_t, const LIEF::MachO::BindingInfo*> fixups;

    for (const LIEF::MachO::Relocation& relocation : binary.relocations()) {
        if (relocation.origin() == LIEF::MachO::Relocation::ORIGIN::DYLDINFO) {
            fixups.emplace(relocation.address(), nullptr);
        }
    }

    for (const LIEF::MachO::BindingInfo& binding : binary.bindings()) {
        fixups[binding.address()] = &binding;
    }

    std::cout << "\n  " << style.bold() << "fixups: " << fixups.size() << style.reset() << '\n';
    printFixupColumns(threaded ? "decoded" : "", style);

    for (const auto& [address, binding] : fixups) {
        FixupRow row;
        row.address = address;
        row.raw = readRawPointer(binary, address).value_or(0);
        row.bind = binding;
        row.next = "-";

        if (threaded) {
            ChainedPointer pointer = ChainedPointer::decode(row.raw, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E);
            row.next = pointer.getNext() ? "+" + std::to_string(pointer.getNext()) : "end";

            if (pointer.getBind()) {
                row.decoded = "ordinal table #" + std::to_string(pointer.getOrdinal());
            } else {
                std::uint64_t target = pointer.rebaseTarget(binary, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E);
                row.decoded = "target " + hex(pointer.getTarget());
                row.resolved = hex(target) + " " + map.describe(target);
            }

            if (pointer.getAuthenticated()) {
                row.decoded += " auth " + pointer.authenticationString();
            }
        } else if (!binding) {
            // A plain pointer, valid at the preferred base address.
            row.resolved = hex(row.raw) + " " + map.describe(row.raw);
        }

        if (binding) {
            row.resolved = bindTarget(binary, binding->has_symbol() ? binding->symbol()->name() : "?", binding->library_ordinal());
        }

        printFixup(row, map, style);
    }
}

void dumpImportTable(const LIEF::MachO::Binary& binary, const std::optional<ImportTable>& table, const Style& style)
{
    if (!table) {
        std::cout << "  " << style.dim() << "(could not read the import table)" << style.reset() << '\n';

        return;
    }

    std::cout << "  " << style.bold()
              << "imports: " << to_string(table->format)
              << ", " << table->imports.size()
              << " entries" << (table->compressedNames ? " (zlib-compressed names, not shown)" : "") << style.reset()
              << '\n';

    for (std::size_t i = 0; i < table->imports.size(); ++i) {
        const ChainedImport& import = table->imports[i];

        std::cout << "    #" << std::left << std::setw(3) << i << ' '
                            << std::setw(28) << import.name << ' '
                            << std::right << std::setw(3) << import.ordinal << std::left << ' '
                            << ordinalName(binary, import.ordinal);

        if (import.weak) {
            std::cout << style.yellow() << "  weak-import" << style.reset();
        }

        std::cout << '\n';
    }
}

// One entry per segment with fixups, and one chain start per page.
void dumpChainStarts(const LIEF::MachO::DyldChainedFixups& fixups, const Style& style)
{
    std::cout << "\n  " << style.bold() << "chains:" << style.reset() << '\n';

    for (const auto& starts : fixups.chained_starts_in_segments()) {
        if (!starts.page_count()) {
            continue;
        }

        std::cout << "    " << std::left << std::setw(14) << starts.segment.name()
                  << ' ' << to_string(starts.pointer_format)
                  << " (" << strideNote(starts.pointer_format) << "), page size " << hex(starts.page_size)
                  << '\n';

        for (std::size_t page = 0; page < starts.page_count(); ++page) {
            std::uint16_t start = starts.page_start[page];

            std::cout << "      page " << std::setw(3) << page << ' ';

            if (start == pageStartNone) {
                std::cout << "no fixups\n";

                continue;
            }

            std::cout << "first fixup at " << hex(starts.segment.virtual_address() + page * starts.page_size + start) << '\n';
        }
    }
}

// Every fixup: the 8 bytes on disk, madamp's decoding of them, and what
// they resolve to, checked against LIEF's own decoding.
bool dumpChainedFixups(const LIEF::MachO::Binary& binary, const LIEF::MachO::DyldChainedFixups& chainedFixups, const AddressMap& map, const Style& style)
{
    std::optional<ImportTable> table = readImportTable(chainedFixups);

    dumpImportTable(binary, table, style);
    dumpChainStarts(chainedFixups, style);

    struct Fixup {
        const LIEF::MachO::ChainedBindingInfo* bind { nullptr };
        const LIEF::MachO::RelocationFixup* rebase { nullptr };
    };

    std::map<std::uint64_t, Fixup> fixups;

    for (const LIEF::MachO::BindingInfo& binding : binary.bindings()) {
        if (const auto* bind = binding.cast<LIEF::MachO::ChainedBindingInfo>()) {
            fixups[bind->address()].bind = bind;
        }
    }

    for (const LIEF::MachO::Relocation& relocation : binary.relocations()) {
        if (const auto* rebase = relocation.cast<LIEF::MachO::RelocationFixup>()) {
            fixups[rebase->address()].rebase = rebase;
        }
    }

    std::cout << "\n  " << style.bold() << "fixups: " << fixups.size() << style.reset() << '\n';
    printFixupColumns("decoded", style);

    bool agrees = true;

    for (const auto& [address, fixup] : fixups) {
        LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format = fixup.bind ? fixup.bind->ptr_format() : fixup.rebase->ptr_format();

        FixupRow row;
        row.address = address;
        row.raw = readRawPointer(binary, address).value_or(0);

        ChainedPointer pointer = ChainedPointer::decode(row.raw, format);
        row.bind = pointer.getBind();

        if (!pointer.getDecoded()) {
            row.next = "?";
            row.decoded = "(format not decoded)";
            printFixup(row, map, style);

            continue;
        }

        row.next = pointer.getNext() ? "+" + std::to_string(pointer.getNext()) : "end";

        if (pointer.getBind()) {
            row.decoded = "import #" + std::to_string(pointer.getOrdinal());

            if (pointer.getAddend()) {
                row.decoded += " + " + hex(static_cast<std::uint64_t>(pointer.getAddend()));
            }

            if (table && pointer.getOrdinal() < table->imports.size()) {
                const ChainedImport& import = table->imports[pointer.getOrdinal()];
                row.resolved = bindTarget(binary, import.name, import.ordinal);

                if (!fixup.bind || !fixup.bind->has_symbol() || fixup.bind->symbol()->name() != import.name) {
                    row.mismatch = "LIEF disagrees";
                }
            }
        } else {
            std::uint64_t target = pointer.rebaseTarget(binary, format);
            row.decoded = "target " + hex(pointer.getTarget());
            row.resolved = hex(target) + " " + map.describe(target);

            if (!fixup.rebase || fixup.rebase->target() != target) {
                row.mismatch = "LIEF disagrees";
            }
        }

        if (pointer.getAuthenticated()) {
            row.decoded += " auth " + pointer.authenticationString();
        }

        if (!row.mismatch.empty()) {
            agrees = false;
        }

        printFixup(row, map, style);
    }

    return agrees;
}

} // namespace

bool dumpFixups(const LIEF::MachO::Binary& binary, const AddressMap& map, const Style& style)
{
    if (const LIEF::MachO::DyldChainedFixups* chainedFixups = binary.dyld_chained_fixups()) {
        printTitle(style, "Fixups (LC_DYLD_CHAINED_FIXUPS)");

        return dumpChainedFixups(binary, *chainedFixups, map, style);
    }

    if (!binary.dyld_info()) {
        printTitle(style, "Fixups");
        std::cout << "  " << style.dim() << "(none: no LC_DYLD_CHAINED_FIXUPS or LC_DYLD_INFO)" << style.reset() << '\n';

        return true;
    }

    printTitle(style, "Fixups (LC_DYLD_INFO)");
    dumpDyldInfoFixups(binary, map, style);

    return true;
}

} // namespace madamp

// EOF