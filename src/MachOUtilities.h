#pragma once

#include <LIEF/MachO/Section.hpp>
#include <mach/vm_prot.h>

#include <cstdint>
#include <string>

namespace madamp {

constexpr auto protectionRead = static_cast<std::uint32_t>(VM_PROT_READ);
constexpr auto protectionWrite = static_cast<std::uint32_t>(VM_PROT_WRITE);
constexpr auto protectionExecute = static_cast<std::uint32_t>(VM_PROT_EXECUTE);

// "r-x" for read and execute, like ls -l.
std::string protectionString(std::uint32_t protection);

// Zero-fill sections (__bss, __common, ...) have no bytes in the file.
bool isZeroFill(const LIEF::MachO::Section& section);

} // namespace madamp

// EOF