#include "Options.h"

#include "Error.h"

#include <charconv>
#include <iostream>

namespace madamp {

namespace {

std::optional<std::uint64_t> parseAddress(const std::string& text)
{
    std::string_view digits = text;
    int base = 10;

    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits.remove_prefix(2);
        base = 16;
    }

    std::uint64_t value = 0;
    auto result = std::from_chars(digits.data(), digits.data() + digits.size(), value, base);

    if (result.ec != std::errc() || result.ptr != digits.data() + digits.size()) {
        return std::nullopt;
    }

    return value;
}

} // namespace

void printUsage(std::ostream& out)
{
    out << R"(usage: madamp [options] <mach-o file>

        -H, --header     Mach header
        -l, --commands   load commands
        -g, --segments   segments: where each one is in the file and in memory
        -s, --sections   sections
        -L, --libs       linked libraries and rpaths
        -x, --hexdump S  hexdump section S ("SEG,SECT" or "SECT"), repeatable
        --addr VA        locate a virtual address: segment, section, symbol, file offset
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
        } else if (argument == "-g" || argument == "--segments") {
            options.m_showSegments = true;
        } else if (argument == "-s" || argument == "--sections") {
            options.m_showSections = true;
        } else if (argument == "-L" || argument == "--libs") {
            options.m_showLibraries = true;
        } else if (argument == "-x" || argument == "--hexdump") {
            if (i + 1 == arguments.size()) {
                printError(argument + " needs a section");

                return std::nullopt;
            }

            options.m_hexdumps.push_back(arguments[++i]);
        } else if (argument == "--addr") {
            if (i + 1 == arguments.size()) {
                printError("--addr needs an address");

                return std::nullopt;
            }

            std::optional<std::uint64_t> address = parseAddress(arguments[++i]);

            if (!address) {
                printError("bad address '" + arguments[i] + "'");

                return std::nullopt;
            }

            options.m_addresses.push_back(*address);
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