#pragma once

#include <LIEF/MachO/FatBinary.hpp>

namespace madamp {

void printSlices(const LIEF::MachO::FatBinary& fat);

} // namespace madamp

// EOF