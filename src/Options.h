#pragma once

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

    bool includesArch(std::string_view arch) const { return m_arch.empty() || m_arch == arch; }

private:
    // With no dump selected, madamp shows everything.
    bool selectsNothing() const { return !m_showHeader && !m_showCommands && !m_showSegments && !m_showSections; }
    void selectAll() { m_showHeader = m_showCommands = m_showSegments = m_showSections = true; }

    std::string m_path;
    std::string m_arch; // empty: every slice
    bool m_showHelp { false };
    bool m_showVersion { false };
    bool m_useColor { false };
    bool m_showHeader { false };
    bool m_showCommands { false };
    bool m_showSegments { false };
    bool m_showSections { false };
};

} // namespace madamp

// EOF