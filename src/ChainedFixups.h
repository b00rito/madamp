#pragma once

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/DyldChainedFixups.hpp>
#include <LIEF/MachO/DyldChainedFormat.hpp>
#include <ptrauth.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace madamp {

// One 64-bit chained-fixup pointer, decoded as it sits on disk.
class ChainedPointer {
public:
    // The arm64e pointer authentication keys
    enum class Key : std::uint8_t {
        IA = ptrauth_key_asia,
        IB = ptrauth_key_asib,
        DA = ptrauth_key_asda,
        DB = ptrauth_key_asdb,
    };

    static ChainedPointer decode(std::uint64_t raw, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format);

    bool getDecoded() const { return m_decoded; }
    bool getBind() const { return m_bind; }
    bool getAuthenticated() const { return m_authenticated; }
    std::uint32_t getNext() const { return m_next; }
    std::uint64_t getTarget() const { return m_target; }
    std::uint32_t getOrdinal() const { return m_ordinal; }
    std::int64_t getAddend() const { return m_addend; }
    Key getKey() const { return m_key; }
    bool getAddressDiversity() const { return m_addressDiversity; }
    std::uint16_t getDiversity() const { return m_diversity; }

    // The address a rebase points to.
    std::uint64_t rebaseTarget(const LIEF::MachO::Binary& binary, LIEF::MachO::DYLD_CHAINED_PTR_FORMAT format) const;

    // "IA", "IB+addr", ...
    std::string authenticationString() const;

private:
    ChainedPointer() = default;

    static ChainedPointer decode64(std::uint64_t raw);
    static ChainedPointer decodeArm64e(std::uint64_t raw, bool wideOrdinals);

    bool m_decoded { false };           // false for formats madamp doesn't decode
    bool m_bind { false };              // a bind (an import), or a rebase (a pointer into this image)
    bool m_authenticated { false };     // arm64e: signed with pointer authentication
    std::uint32_t m_next { 0 };         // bytes to the next fixup on the page; 0 ends the chain
    std::uint64_t m_target { 0 };       // rebase: a vmaddr, or an offset from the image base
    std::uint32_t m_ordinal { 0 };      // bind: an index into the import table
    std::int64_t m_addend { 0 };        // bind: added to the bound symbol's address
    Key m_key { Key::IA };              // authenticated: the PAC key
    bool m_addressDiversity { false };  // authenticated: the signature also mixes in the pointer's own address
    std::uint16_t m_diversity { 0 };    // authenticated: an extra discriminator
};

// One entry of the LC_DYLD_CHAINED_FIXUPS import table.
struct ChainedImport {
    std::int32_t ordinal { 0 };
    bool weak { false };
    std::int64_t addend { 0 };
    std::string name;
};

struct ImportTable {
    LIEF::MachO::DYLD_CHAINED_FORMAT format { LIEF::MachO::DYLD_CHAINED_FORMAT::IMPORT };
    bool compressedNames { false }; // zlib-compressed: names not read
    std::vector<ChainedImport> imports;
};

// LIEF has the bindings but not the import table they index into, so
// madamp reads it from the command's payload. Empty if the table is
// malformed or in a format madamp doesn't know.
std::optional<ImportTable> readImportTable(const LIEF::MachO::DyldChainedFixups& fixups);

// The 8 bytes at an address, as stored in the file. Empty if there are no
// file bytes there.
std::optional<std::uint64_t> readRawPointer(const LIEF::MachO::Binary& binary, std::uint64_t address);

} // namespace madamp

// EOF
