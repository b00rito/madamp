#pragma once

#include <cstdint>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace madamp {

constexpr std::string_view version = "0.1.0";

void printUsage(std::ostream& out);

class Options {
public:
    static std::optional<Options> parse(const std::vector<std::string>& arguments);

    const std::string& getPath() const { return m_path; }
    const std::string& getArch() const { return m_arch; }
    bool getShowHelp() const { return m_showHelp; }
    bool getShowVersion() const { return m_showVersion; }
    bool getUseColor() const { return m_useColor; }
    bool getShowHeader() const { return m_showHeader; }
    bool getShowCommands() const { return m_showCommands; }
    bool getShowSegments() const { return m_showSegments; }
    bool getShowSections() const { return m_showSections; }
    bool getShowLibraries() const { return m_showLibraries; }
    bool getShowSymbols() const { return m_showSymbols; }
    bool getShowFixups() const { return m_showFixups; }
    const std::vector<std::string>& getHexdumps() const { return m_hexdumps; }
    const std::vector<std::uint64_t>& getAddresses() const { return m_addresses; }
    const std::vector<std::string>& getDisassemblies() const { return m_disassemblies; }

    bool includesArch(std::string_view arch) const { return m_arch.empty() || m_arch == arch; }

private:
    // With no dump selected, madamp shows everything.
    // --hexdump, --addr and --disasm on their own show just that.
    bool selectsNothing() const { return !m_showHeader && !m_showCommands && !m_showSegments && !m_showSections && !m_showLibraries && !m_showSymbols && !m_showFixups && m_hexdumps.empty() && m_addresses.empty() && m_disassemblies.empty(); }
    void selectAll() { m_showHeader = m_showCommands = m_showSegments = m_showSections = m_showLibraries = m_showSymbols = m_showFixups = true; }

    std::string m_path;
    std::string m_arch; // empty: every slice
    bool m_showHelp { false };
    bool m_showVersion { false };
    bool m_useColor { false };
    bool m_showHeader { false };
    bool m_showCommands { false };
    bool m_showSegments { false };
    bool m_showSections { false };
    bool m_showLibraries { false };
    bool m_showSymbols { false };
    bool m_showFixups { false };
    std::vector<std::string> m_hexdumps;
    std::vector<std::uint64_t> m_addresses;
    std::vector<std::string> m_disassemblies;
};

} // namespace madamp

// EOF