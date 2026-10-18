#include "ChainedFixups.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/DyldChainedFixups.hpp>
#include <LIEF/MachO/DyldChainedFormat.hpp>
#include <mach-o/fixup-chains.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <type_traits>

namespace madamp {

namespace {

// A T copied out of raw bytes, the way dyld reads its structs. Empty if
// the bytes are too short.
template<typename T>
std::optional<T> readAt(LIEF::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return std::nullopt;
    }

    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));

    return value;
}

// The pointer formats are bitfield structs in <mach-o/fixup-chains.h>;
// this reinterprets a raw pointer as one of them.
template<typename Bits>
Bits bitsOf(std::uint64_t raw)
{
    static_assert(sizeof(Bits) == sizeof(raw));

    Bits bits;
    std::memcpy(&bits, &raw, sizeof(bits));

    return bits;
}

// The addend of an arm64e bind is a signed 19-bit field.
std::int64_t signExtendAddend(std::uint64_t addend)
{
    constexpr std::uint64_t signBit = 1ULL << 18;

    if (addend & signBit) {
        return static_cast<std::int64_t>(addend) - static_cast<std::int64_t>(signBit << 1);
    }

    return static_cast<std::int64_t>(addend);
}

// The high8 bits of a rebase go to the top byte of the pointer, for
// tagged pointers.
std::uint64_t withHigh8(std::uint64_t target, std::uint64_t high8)
{
    return target | (high8 << 56);
}

// One import table entry; the three formats differ in field widths and
// in whether there is an addend.
template<typename Entry>
std::optional<ChainedImport> readImport(LIEF::span<const std::uint8_t> payload, std::size_t offset, std::uint64_t& nameOffset)
{
    std::optional<Entry> entry = readAt<Entry>(payload, offset);

    if (!entry) {
        return std::nullopt;
    }

    ChainedImport import;
    import.weak = entry->weak_import;
    nameOffset = entry->name_offset;

    if constexpr (std::is_same_v<Entry, dyld_chained_import_addend64>) {
        import.ordinal = static_cast<std::int16_t>(entry->lib_ordinal);
        import.addend = static_cast<std::int64_t>(entry->addend);
    } else {
        import.ordinal = static_cast<std::int8_t>(entry->lib_ordinal);
    }

    if constexpr (std::is_same_v<Entry, dyld_chained_import_addend>) {
        import.addend = entry->addend;
    }

    return import;
}

std::string readName(LIEF::span<const std::uint8_t> payload, std::size_t offset)
{
    if (offset >= payload.size()) {
        return { };
    }

    auto begin = payload.begin() + offset;
    auto end = std::find(begin, payload.end(), 0);

    return std::string(begin, end);
}

std::string_view keyName(ChainedPointer::Key key)
{
    switch (key) {
    case ChainedPointer::Key::IA:
        return "IA";
    case ChainedPointer::Key::IB:
        return "IB";
    case ChainedPointer::Key::DA:
        return "DA";
    case ChainedPointer::Key::DB:
        return "DB";
    }

    return "?";
}

} // namespace

ChainedPointer ChainedPointer::decode64(std::uint64_t raw)
{
    ChainedPointer pointer;
    auto rebase = bitsOf<dyld_chained_ptr_64_rebase>(raw);

    pointer.m_decoded = true;
    pointer.m_bind = rebase.bind;
    pointer.m_next = static_cast<std::uint32_t>(rebase.next) * 4;

    if (!pointer.m_bind) {
        pointer.m_target = withHigh8(rebase.target, rebase.high8);

        return pointer;
    }

    auto bind = bitsOf<dyld_chained_ptr_64_bind>(raw);
    pointer.m_ordinal = bind.ordinal;
    pointer.m_addend = bind.addend;

    return pointer;
}

// The top two bits (auth, bind) are the same in every arm64e variant and
// pick which struct the other 62 follow.
ChainedPointer ChainedPointer::decodeArm64e(std::uint64_t raw, bool wideOrdinals)
{
    ChainedPointer pointer;
    auto rebase = bitsOf<dyld_chained_ptr_arm64e_rebase>(raw);

    pointer.m_decoded = true;
    pointer.m_authenticated = rebase.auth;
    pointer.m_bind = rebase.bind;
    pointer.m_next = static_cast<std::uint32_t>(rebase.next) * 8;

    if (pointer.m_authenticated && pointer.m_bind) {
        if (wideOrdinals) {
            auto bind = bitsOf<dyld_chained_ptr_arm64e_auth_bind24>(raw);
            pointer.m_ordinal = bind.ordinal;
            pointer.m_diversity = bind.diversity;
            pointer.m_addressDiversity = bind.addrDiv;
            pointer.m_key = static_cast<Key>(bind.key);

            return pointer;
        }

        auto bind = bitsOf<dyld_chained_ptr_arm64e_auth_bind>(raw);
        pointer.m_ordinal = bind.ordinal;
        pointer.m_diversity = bind.diversity;
        pointer.m_addressDiversity = bind.addrDiv;
        pointer.m_key = static_cast<Key>(bind.key);

        return pointer;
    }

    if (pointer.m_authenticated) {
        auto authRebase = bitsOf<dyld_chained_ptr_arm64e_auth_rebase>(raw);
        pointer.m_target = authRebase.target;
        pointer.m_diversity = authRebase.diversity;
        pointer.m_addressDiversity = authRebase.addrDiv;
        pointer.m_key = static_cast<Key>(authRebase.key);

        return pointer;
    }

    if (pointer.m_bind) {
        if (wideOrdinals) {
            auto bind = bitsOf<dyld_chained_ptr_arm64e_bind24>(raw);
            pointer.m_ordinal = bind.ordinal;
            pointer.m_addend = signExtendAddend(bind.addend);

            return pointer;
        }

        auto bind = bitsOf<dyld_chained_ptr_arm64e_bind>(raw);
        pointer.m_ordinal = bind.ordinal;
        pointer.m_addend = signExtendAddend(bind.addend);

        return pointer;
    }

    pointer.m_target = withHigh8(rebase.target, rebase.high8);

    return pointer;
}

ChainedPointer ChainedPointer::decode(std::uint64_t raw, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format)
{
    switch (format) {
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_64:
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET:
        return decode64(raw);
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E:
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND:
        return decodeArm64e(raw, false);
    case LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24:
        return decodeArm64e(raw, true);
    default:
        return ChainedPointer();
    }
}

std::uint64_t ChainedPointer::rebaseTarget(const LIEF::MachO::Binary& binary, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format) const
{
    // Authenticated rebases always store an offset from the image base;
    // plain ones store an address in PTR_64 and PTR_ARM64E.
    bool isOffset = m_authenticated || format == LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_64_OFFSET || format == LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND || format == LIEF::MachO::DYLD_CHAINED_PTR_FORMAT::PTR_ARM64E_USERLAND24;

    if (isOffset) {
        return binary.imagebase() + m_target;
    }

    return m_target;
}

std::string ChainedPointer::authenticationString() const
{
    std::string text(keyName(m_key));

    if (m_addressDiversity) {
        text += "+addr";
    }

    return text;
}

std::optional<ImportTable> readImportTable(const LIEF::MachO::DyldChainedFixups& fixups)
{
    LIEF::span<const std::uint8_t> payload = fixups.payload();
    std::optional<dyld_chained_fixups_header> header = readAt<dyld_chained_fixups_header>(payload, 0);

    if (!header) {
        return std::nullopt;
    }

    ImportTable table;
    table.format = static_cast<LIEF::MachO::DYLD_CHAINED_FORMAT>(header->imports_format);
    table.compressedNames = header->symbols_format != 0;

    for (std::uint32_t i = 0; i < header->imports_count; ++i) {
        std::optional<ChainedImport> import;
        std::uint64_t nameOffset = 0;

        switch (header->imports_format) {
        case DYLD_CHAINED_IMPORT:
            import = readImport<dyld_chained_import>(payload, header->imports_offset + i * sizeof(dyld_chained_import), nameOffset);
            break;
        case DYLD_CHAINED_IMPORT_ADDEND:
            import = readImport<dyld_chained_import_addend>(payload, header->imports_offset + i * sizeof(dyld_chained_import_addend), nameOffset);
            break;
        case DYLD_CHAINED_IMPORT_ADDEND64:
            import = readImport<dyld_chained_import_addend64>(payload, header->imports_offset + i * sizeof(dyld_chained_import_addend64), nameOffset);
            break;
        default:
            return std::nullopt;
        }

        if (!import) {
            return std::nullopt;
        }

        if (!table.compressedNames) {
            import->name = readName(payload, header->symbols_offset + nameOffset);
        }

        table.imports.push_back(*import);
    }

    return table;
}

std::optional<std::uint64_t> readRawPointer(const LIEF::MachO::Binary& binary, std::uint64_t address)
{
    return readAt<std::uint64_t>(binary.get_content_from_virtual_address(address, sizeof(std::uint64_t)), 0);
}

} // namespace madamp

// EOF
