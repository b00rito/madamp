#pragma once

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/Section.hpp>
#include <LIEF/MachO/SegmentCommand.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace madamp {

struct Location {
    const LIEF::MachO::SegmentCommand* segment { nullptr };
    const LIEF::MachO::Section* section { nullptr };
    std::optional<std::uint64_t> sliceOffset;   // empty: no bytes on disk
    std::string symbol;
    std::string import;     // "_printf (stub)", "_printf (GOT)" or empty
    std::string cstring;
};

/*
 * Lookup tables built once per slice. The defined symbols by address and
 * the stub and GOT slots that the indirect symbol table ties to imported
 * symbols.
 */
class AddressMap {
public:
    explicit AddressMap(const LIEF::MachO::Binary& binary);

    Location locate(std::uint64_t address) const;

private:
    // The map doesn't own the binary and must not outlive it.
    const LIEF::MachO::Binary& m_binary;
    std::map<std::uint64_t, std::string> m_symbols;
    std::map<std::uint64_t, std::string> m_imports;
};

} // namespace madamp

// EOF