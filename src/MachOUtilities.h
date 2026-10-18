#pragma once

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/DylibCommand.hpp>
#include <LIEF/MachO/Section.hpp>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>

#include <cstdint>
#include <string>
#include <vector>

namespace madamp {

constexpr auto protectionRead = static_cast<std::uint32_t>(VM_PROT_READ);
constexpr auto protectionWrite = static_cast<std::uint32_t>(VM_PROT_WRITE);
constexpr auto protectionExecute = static_cast<std::uint32_t>(VM_PROT_EXECUTE);

// Library ordinals with a special meaning instead of a library.
constexpr auto ordinalSelf = static_cast<std::int32_t>(BIND_SPECIAL_DYLIB_SELF);
constexpr auto ordinalMainExecutable = static_cast<std::int32_t>(BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE);
constexpr auto ordinalFlatLookup = static_cast<std::int32_t>(BIND_SPECIAL_DYLIB_FLAT_LOOKUP);
constexpr auto ordinalWeakLookup = static_cast<std::int32_t>(BIND_SPECIAL_DYLIB_WEAK_LOOKUP);

// "r-x" for read and execute, like ls -l.
std::string protectionString(std::uint32_t protection);

// Zero-fill sections (__bss, __common, ...) have no bytes in the file.
bool isZeroFill(const LIEF::MachO::Section& section);

// A section named "SEG,SECT" or just "SECT" - the first occurrence.
const LIEF::MachO::Section* findSection(const LIEF::MachO::Binary& binary, const std::string& name);

// The dylibs in library-ordinal order: ordinal 1 is the first
// LC_LOAD_*DYLIB command. Unlike Binary::libraries(), this leaves out
// LC_ID_DYLIB, a dylib's own name.
std::vector<const LIEF::MachO::DylibCommand*> loadedLibraries(const LIEF::MachO::Binary& binary);

// "@rpath/libcolors.dylib" for ordinal 1 of build/app or what a special
// ordinal means.
std::string ordinalName(const LIEF::MachO::Binary& binary, std::int32_t ordinal);

} // namespace madamp

// EOF