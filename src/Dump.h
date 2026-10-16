#pragma once

#include "AddressMap.h"
#include "Options.h"
#include "Style.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat, const Style& style);

bool dumpSlice(const LIEF::MachO::Binary& binary, const Options& options, const Style& style);

void printTitle(const Style& style, std::string_view title);

void dumpHeader(const LIEF::MachO::Binary& binary, const Style& style);
void dumpCommands(const LIEF::MachO::Binary& binary, const Style& style);
void dumpSegments(const LIEF::MachO::Binary& binary, const Style& style);
void dumpSections(const LIEF::MachO::Binary& binary, const Style& style);
void dumpLibraries(const LIEF::MachO::Binary& binary, const Style& style);
bool dumpHexdump(const LIEF::MachO::Binary& binary, const std::string& sectionName, const Style& style);
void dumpAddress(const LIEF::MachO::Binary& binary, const AddressMap& map, std::uint64_t address, const Style& style);

} // namespace madamp

// EOF