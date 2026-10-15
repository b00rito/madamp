#pragma once

#include "Options.h"
#include "Style.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

#include <string_view>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat, const Style& style);

bool dumpSlice(const LIEF::MachO::Binary& binary, const Options& options, const Style& style);

void printTitle(const Style& style, std::string_view title);

void dumpHeader(const LIEF::MachO::Binary& binary, const Style& style);
void dumpCommands(const LIEF::MachO::Binary& binary, const Style& style);
void dumpSegments(const LIEF::MachO::Binary& binary, const Style& style);

} // namespace madamp

// EOF