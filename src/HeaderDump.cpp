#include "Architecture.h"
#include "Dump.h"
#include "Format.h"
#include "Style.h"

#include <LIEF/MachO.hpp>

#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>

namespace madamp {

namespace {

// The UUID in its usual form: 8-4-4-4-12 uppercase hex digits.
std::string uuidString(const LIEF::MachO::uuid_t& uuid)
{
    constexpr std::string_view digits = "0123456789ABCDEF";
    std::string text;

    for (std::size_t i = 0; i < uuid.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            text += '-';
        }

        text += digits[uuid[i] >> 4];
        text += digits[uuid[i] & 0xf];
    }

    return text;
}

std::ostream& field(std::string_view label)
{
    return std::cout << "  " << std::left << std::setw(14) << label << ' ';
}

} // namespace

void dumpHeader(const LIEF::MachO::Binary& binary, const Style& style)
{
    const LIEF::MachO::Header& header = binary.header();

    printTitle(style, "Mach header");
    field("cpu") << archName(binary) << '\n';
    field("cpu subtype") << hex(header.cpu_subtype()) << '\n';
    field("file type") << to_string(header.file_type()) << '\n';
    field("load commands") << header.nb_cmds() << " (" << header.sizeof_cmds() << " bytes)\n";

    std::string flags;

    for (LIEF::MachO::Header::FLAGS flag : header.flags_list()) {
        if (!flags.empty()) {
            flags += " | ";
        }

        flags += to_string(flag);
    }

    field("flags") << flags << '\n';
    field("image base") << hex(binary.imagebase(), 16) << '\n';
    field("VM size") << hex(binary.virtual_size()) << " bytes\n";

    if (binary.fat_offset() != 0) {
        field("fat offset") << hex(binary.fat_offset()) << '\n';
    }

    // LC_MAIN stores the entry point as an offset from the start of
    // __TEXT, not as an address.
    if (const LIEF::MachO::MainCommand* main = binary.main_command()) {
        field("entrypoint") << hex(binary.imagebase() + main->entrypoint(), 16) << " (LC_MAIN offset " << hex(main->entrypoint()) << ")\n";
    }

    if (const LIEF::MachO::UUIDCommand* uuid = binary.uuid()) {
        field("uuid") << uuidString(uuid->uuid()) << '\n';
    }

    if (const LIEF::MachO::BuildVersion* build = binary.build_version()) {
        field("platform") << to_string(build->platform()) << ", minos " << versionString(build->minos()) << ", sdk " << versionString(build->sdk()) << '\n';
    }

    bool encrypted = binary.has_encryption_info() && binary.encryption_info()->crypt_id() != 0;

    auto yesOrNo = [](bool value) { return value ? "yes" : "no"; };

    field("security") << "PIE=" << yesOrNo(binary.is_pie())
                      << " NX=" << yesOrNo(binary.has_nx())
                      << " codesign=" << yesOrNo(binary.has_code_signature())
                      << " encrypted=" << yesOrNo(encrypted) << '\n';
}

} // namespace madamp

// EOF
