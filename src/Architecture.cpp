#include "Architecture.h"

#include <LIEF/MachO/Binary.hpp>

namespace madamp {

std::string_view
archName(const LIEF::MachO::Binary& binary)
{
    const LIEF::MachO::Header& header = binary.header();

    return archName(header.cpu_type(), header.cpu_subtype());
}

} // namespace madamp

// EOF