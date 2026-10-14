#pragma once

#include "Options.h"
#include "Style.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat, const Style& style);

bool dumpSlice(const LIEF::MachO::Binary& binary, const Options& options, const Style& style);

} // namespace madamp

// EOF
