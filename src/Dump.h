#pragma once

#include "Options.h"

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/FatBinary.hpp>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat);

bool dumpSlice(const LIEF::MachO::Binary& binary, const Options& options);

} // namespace madamp

// EOF