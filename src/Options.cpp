#include "Options.h"

#include "Error.h"

#include <iostream>

namespace madamp {

void printUsage(std::ostream& out)
{
    out << R"(usage: madamp [options] <mach-o file>

        -H, --header     Mach header
        -l, --commands   load commands
        -a, --all        everything (the default when no dump is selected)
        --arch NAME      only dump this slice (arm64, arm64e, x86_64, ...)
        --color          use ANSI colors
        -h, --help       show this help
        --version        show the version
)";
}

std::optional<Options> Options::parse(const std::vector<std::string>& arguments)
{
    Options options;

    for (std::size_t i = 0; i < arguments.size(); ++i) {
        const std::string& argument = arguments[i];

        if (argument == "-h" || argument == "--help") {
            options.m_showHelp = true;
        } else if (argument == "--version") {
            options.m_showVersion = true;
        } else if (argument == "--color") {
            options.m_useColor = true;
        } else if (argument == "-H" || argument == "--header") {
            options.m_showHeader = true;
        } else if (argument == "-l" || argument == "--commands") {
            options.m_showCommands = true;
        } else if (argument == "-a" || argument == "--all") {
            options.selectAll();
        } else if (argument == "--arch") {
            if (i + 1 == arguments.size()) {
                printError("--arch needs a value");

                return std::nullopt;
            }

            options.m_arch = arguments[++i];
        } else if (argument.size() > 1 && argument.front() == '-') {
            printError("unknown option '" + argument + "'");

            return std::nullopt;
        } else if (!options.m_path.empty()) {
            printError("only one file at a time");

            return std::nullopt;
        } else {
            options.m_path = argument;
        }
    }

    bool wantsInfoOnly = options.m_showHelp || options.m_showVersion;

    if (options.m_path.empty() && !wantsInfoOnly) {
        printError("no input file");

        return std::nullopt;
    }

    if (options.selectsNothing()) {
        options.selectAll();
    }

    return options;
}

} // namespace madamp

// EOF
