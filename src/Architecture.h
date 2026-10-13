#pragma once

#include <LIEF/MachO/Binary.hpp>
#include <LIEF/MachO/Header.hpp>
#include <mach/machine.h>

#include <cstdint>
#include <string_view>

namespace madamp {

// A CPU subtype has two parts (see <mach/machine.h>). The top 8 bits
// are feature flags, and the rest picks the CPU variant.
constexpr auto cpuSubtypeFeatureMask = static_cast<std::uint32_t>(CPU_SUBTYPE_MASK);
constexpr auto cpuSubtypeArm64e = static_cast<std::uint32_t>(CPU_SUBTYPE_ARM64E);

// LIEF reports arm64e slices as CPU_TYPE::ARM64, so the "e" has to come
// from the subtype, the same check dyld makes.
constexpr std::string_view
archName(LIEF::MachO::Header::CPU_TYPE type, std::uint32_t subtype)
{
    switch (type) {
    case LIEF::MachO::Header::CPU_TYPE::ARM64:
        if ((subtype & ~cpuSubtypeFeatureMask) == cpuSubtypeArm64e) {
            return "arm64e";
        }

        return "arm64";
    case LIEF::MachO::Header::CPU_TYPE::X86_64:
        return "x86_64";
    case LIEF::MachO::Header::CPU_TYPE::X86:
        return "i386";
    case LIEF::MachO::Header::CPU_TYPE::ARM:
        return "arm";
    default:
        return "unknown";
    }
}

// 0x80000002 is arm64e plus the CPU_SUBTYPE_PTRAUTH_ABI flag
static_assert(archName(LIEF::MachO::Header::CPU_TYPE::ARM64, 0) == "arm64");
static_assert(archName(LIEF::MachO::Header::CPU_TYPE::ARM64, 0x80000002) == "arm64e");
static_assert(archName(LIEF::MachO::Header::CPU_TYPE::X86_64, 3) == "x86_64");

// The architecture of one slice
std::string_view archName(const LIEF::MachO::Binary& binary);

} // namespace madamp

// EOF