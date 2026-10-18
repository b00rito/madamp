#include "AddressMap.h"
#include "Architecture.h"
#include "Dump.h"
#include "Error.h"
#include "Format.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>
#include <capstone.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace madamp {

namespace {

/*
 * Owns Capstone's handle and instruction buffer, and frees both in its
 * destructor.
*/
class Capstone {
public:
    Capstone(cs_arch architecture, cs_mode mode)
    {
        if (cs_open(architecture, mode, &m_handle) != CS_ERR_OK) {
            return;
        }

        m_isOpen = true;
        cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
        m_instruction.reset(cs_malloc(m_handle));
    }

    ~Capstone()
    {
        // Free the buffer before the handle it was allocated for.
        m_instruction.reset();

        if (m_isOpen) {
            cs_close(&m_handle);
        }
    }

    // A copy would close the same handle twice, so copying is deleted.
    Capstone(const Capstone&) = delete;
    Capstone& operator=(const Capstone&) = delete;

    bool isOpen() const { return m_isOpen && m_instruction; }
    csh handle() const { return m_handle; }
    cs_insn& instruction() { return *m_instruction; }

private:
    struct InstructionDeleter {
        void operator()(cs_insn* instruction) const { cs_free(instruction, 1); }
    };

    csh m_handle { 0 };
    bool m_isOpen { false };
    std::unique_ptr<cs_insn, InstructionDeleter> m_instruction;
};

// The target of a relative branch or call: its last immediate operand
// (`tbnz w8, #0, target` has two immediates; the target is the last).
std::optional<std::uint64_t> branchTarget(csh handle, const cs_insn& instruction, bool isArm64)
{
    if (!cs_insn_group(handle, &instruction, CS_GRP_BRANCH_RELATIVE)) {
        return std::nullopt;
    }

    std::optional<std::uint64_t> target;

    if (isArm64) {
        const cs_arm64& detail = instruction.detail->arm64;

        for (std::uint8_t i = 0; i < detail.op_count; ++i) {
            if (detail.operands[i].type == ARM64_OP_IMM) {
                target = detail.operands[i].imm;
            }
        }

        return target;
    }

    const cs_x86& detail = instruction.detail->x86;

    for (std::uint8_t i = 0; i < detail.op_count; ++i) {
        if (detail.operands[i].type == X86_OP_IMM) {
            target = detail.operands[i].imm;
        }
    }

    return target;
}

// arm64 can't encode a 64-bit address in one instruction, so code builds
// it in two:
//   adrp x0, <page>          ; x0 = the 4 KiB page of the target
//   add  x0, x0, #<offset>   ; or ldr/str [x0, #<offset>]
// The tracker remembers which registers hold a page from adrp and
// resolves the instruction that completes the address.
class Arm64PageTracker {
public:
    std::optional<std::uint64_t> process(csh handle, const cs_insn& instruction)
    {
        const cs_arm64& detail = instruction.detail->arm64;

        if (instruction.id == ARM64_INS_ADRP && detail.op_count == 2) {
            forgetWritten(handle, instruction);
            m_pages[detail.operands[0].reg] = detail.operands[1].imm;

            return std::nullopt;
        }

        std::optional<std::uint64_t> reference;
        bool isAddImmediate = instruction.id == ARM64_INS_ADD && detail.op_count == 3 && detail.operands[1].type == ARM64_OP_REG && detail.operands[2].type == ARM64_OP_IMM;

        if (isAddImmediate) {
            if (auto page = m_pages.find(detail.operands[1].reg); page != m_pages.end()) {
                reference = page->second + detail.operands[2].imm;
            }
        }

        for (std::uint8_t i = 0; i < detail.op_count && !reference; ++i) {
            const cs_arm64_op& operand = detail.operands[i];

            if (operand.type != ARM64_OP_MEM || operand.mem.index != ARM64_REG_INVALID) {
                continue;
            }

            if (auto page = m_pages.find(operand.mem.base); page != m_pages.end()) {
                reference = page->second + operand.mem.disp;
            }
        }

        forgetWritten(handle, instruction);

        return reference;
    }

private:
    // A register the instruction overwrites no longer holds a page.
    void forgetWritten(csh handle, const cs_insn& instruction)
    {
        std::array<std::uint16_t, 64> read {};
        std::array<std::uint16_t, 64> written {};
        std::uint8_t readCount = 0;
        std::uint8_t writtenCount = 0;

        if (cs_regs_access(handle, &instruction, read.data(), &readCount, written.data(), &writtenCount) != CS_ERR_OK) {
            // Capstone can't tell: forget everything, to be safe.
            m_pages.clear();

            return;
        }

        for (std::uint8_t i = 0; i < writtenCount; ++i) {
            m_pages.erase(written[i]);
        }
    }

    std::map<unsigned, std::uint64_t> m_pages;
};

// x86_64 addresses data relative to the *next* instruction:
// [rip + disp].
std::optional<std::uint64_t> ripRelative(const cs_insn& instruction)
{
    const cs_x86& detail = instruction.detail->x86;

    for (std::uint8_t i = 0; i < detail.op_count; ++i) {
        const cs_x86_op& operand = detail.operands[i];

        if (operand.type == X86_OP_MEM && operand.mem.base == X86_REG_RIP) {
            return instruction.address + instruction.size + operand.mem.disp;
        }
    }

    return std::nullopt;
}

bool disassemble(const AddressMap& map, std::uint64_t address, LIEF::span<const std::uint8_t> code, const Style& style)
{
    const LIEF::MachO::Binary& binary = map.binary();
    LIEF::MachO::Header::CPU_TYPE cpu = binary.header().cpu_type();
    bool isArm64 = cpu == LIEF::MachO::Header::CPU_TYPE::ARM64;

    if (!isArm64 && cpu != LIEF::MachO::Header::CPU_TYPE::X86_64) {
        printError("--disasm supports arm64 and x86_64, not " + std::string(archName(binary)));

        return false;
    }

    Capstone capstone(isArm64 ? CS_ARCH_ARM64 : CS_ARCH_X86, isArm64 ? CS_MODE_ARM : CS_MODE_64);

    if (!capstone.isOpen()) {
        printError("Capstone could not be opened");

        return false;
    }

    Arm64PageTracker pages;
    cs_insn& instruction = capstone.instruction();

    // cs_disasm_iter() decodes one instruction and moves these three
    // forward past it.
    const std::uint8_t* bytes = code.data();
    std::size_t remaining = code.size();
    std::uint64_t pc = address;

    while (remaining) {
        std::uint64_t at = pc;

        if (std::optional<std::string_view> label = map.symbolAt(at)) {
            std::cout << style.bold() << *label << ":" << style.reset() << '\n';
        }

        if (!cs_disasm_iter(capstone.handle(), &bytes, &remaining, &pc, &instruction)) {
            // Data in code, or an encoding Capstone doesn't know: show it
            // and step over it.
            std::size_t skip = std::min<std::size_t>(isArm64 ? 4 : 1, remaining);

            std::cout << "  " << style.cyan()
                              << hex(at, 16).substr(2)
                              << style.reset()
                              << "  "
                              << style.dim()
                              << ".byte (undecodable)"
                              << style.reset() << '\n';
            bytes += skip;
            remaining -= skip;
            pc += skip;

            continue;
        }

        std::string encoding;

        for (std::uint16_t i = 0; i < instruction.size && i < 8; ++i) {
            encoding += byteHex(instruction.bytes[i]) + " ";
        }

        if (instruction.size > 8) {
            encoding += "..";
        }

        std::optional<std::uint64_t> reference = branchTarget(capstone.handle(), instruction, isArm64);

        if (!reference && isArm64) {
            reference = pages.process(capstone.handle(), instruction);
        } else if (!reference) {
            reference = ripRelative(instruction);
        } else if (isArm64) {
            // Keep the register tracking up to date across branches too.
            pages.process(capstone.handle(), instruction);
        }

        std::cout << "  " << style.cyan()
                          << hex(instruction.address, 16).substr(2)
                          << style.reset()
                          << "  "
                          << style.dim()
                          << std::left
                          << std::setw(25)
                          << encoding
                          << style.reset()
                          << ' '
                          << std::setw(7)
                          << instruction.mnemonic
                          << ' '
                          << std::setw(28)
                          << instruction.op_str;

        if (reference) {
            std::string description = map.describe(*reference);

            std::cout << ' ' << style.yellow() << "; " << hex(*reference) << (description.empty() ? "" : " ") << description << style.reset();
        }

        std::cout << '\n';
    }

    return true;
}

} // namespace

bool dumpDisassembly(const LIEF::MachO::Binary& binary, const AddressMap& map, const std::string& name, const Style& style)
{
    const LIEF::MachO::Section* section = findSection(binary, name);
    std::uint64_t start = 0;
    std::uint64_t end = 0;

    if (section) {
        start = section->address();
        end = start + section->size();
    } else if (std::optional<std::uint64_t> address = map.symbolAddress(name)) {
        // A function runs until the next symbol or the end of its
        // section.
        section = binary.section_from_virtual_address(*address);

        if (!section) {
            return false;
        }

        start = *address;
        end = section->address() + section->size();

        if (std::optional<std::uint64_t> next = map.nextSymbol(start)) {
            end = std::min(end, *next);
        }
    } else {
        printError("no section or symbol '" + name + "' in the " + std::string(archName(binary)) + " slice");

        return false;
    }

    printTitle(style, "Disassembly " + name);

    LIEF::span<const std::uint8_t> bytes = section->content();

    return disassemble(map, start, bytes.subspan(start - section->address(), end - start), style);
}

} // namespace madamp

// EOF