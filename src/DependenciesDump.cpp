#include "Architecture.h"
#include "Dump.h"
#include "MachOUtilities.h"
#include "Style.h"

#include <LIEF/MachO.hpp>
#include <mach-o/dyld.h>

#include <filesystem>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace madamp {

namespace {

// dyld gives up on load chains deeper than this; so does madamp.
constexpr int maximumDepth = 32;

// An LC_RPATH, with the directory of the image that declared it:
// @loader_path in an rpath means that image's directory.
struct RPath {
    std::string path;
    std::string loaderDirectory;
};

enum class Found {
    OnDisk,
    InSharedCache,
    Missing,
};

struct Resolution {
    Found found { Found::Missing };
    std::string path;               // the file, or the install name if it's not on disk
    std::string via;                // the rpath that matched, if @rpath was used
    std::vector<std::string> tried; // rpaths that didn't match
};

std::string directoryOf(const std::string& path)
{
    return std::filesystem::path(path).parent_path().string();
}

std::string fileNameOf(const std::string& path)
{
    return std::filesystem::path(path).filename().string();
}

std::string normalize(const std::string& path)
{
    std::error_code error;
    std::filesystem::path canonical = std::filesystem::weakly_canonical(path, error);

    if (error) {
        return std::filesystem::path(path).lexically_normal().string();
    }

    return canonical.string();
}

// Paths under the current directory are shown relative to it
std::string display(const std::string& path)
{
    std::error_code error;
    std::filesystem::path relative = std::filesystem::proximate(path, std::filesystem::current_path(), error);

    if (error || relative.string().rfind("..", 0) == 0) {
        return path;
    }

    return relative.string();
}

bool replacePrefix(std::string& text, std::string_view prefix, const std::string& replacement)
{
    if (text.rfind(prefix, 0) != 0) {
        return false;
    }

    text = replacement + text.substr(prefix.size());

    return true;
}

// Since macOS 11, system dylibs exist only inside the dyld shared cache,
// not as files. LIEF reads the cache only in its commercial build, but
// dyld can say what's in the cache of this Mac.
Found locate(const std::string& path)
{
    if (std::filesystem::exists(path)) {
        return Found::OnDisk;
    }

    if (_dyld_shared_cache_contains_path(path.c_str())) {
        return Found::InSharedCache;
    }

    return Found::Missing;
}

std::string_view kindTag(LIEF::MachO::LoadCommand::TYPE type)
{
    switch (type) {
    case LIEF::MachO::LoadCommand::TYPE::LOAD_WEAK_DYLIB:
        return " [weak]";
    case LIEF::MachO::LoadCommand::TYPE::REEXPORT_DYLIB:
        return " [re-export]";
    case LIEF::MachO::LoadCommand::TYPE::LOAD_UPWARD_DYLIB:
        return " [upward]";
    case LIEF::MachO::LoadCommand::TYPE::LAZY_LOAD_DYLIB:
        return " [lazy]";
    default:
        return "";
    }
}

const LIEF::MachO::Binary* findSlice(const LIEF::MachO::FatBinary& fat, std::string_view arch)
{
    for (const LIEF::MachO::Binary& binary : fat) {
        if (archName(binary) == arch) {
            return &binary;
        }
    }

    return nullptr;
}

// Follows the dylibs of one slice the way dyld does, and prints them as
// a tree or as a Graphviz graph.
class DependencyWalker {
public:
    enum class Output {
        Tree,
        Graph,
    };

    DependencyWalker(std::string_view arch, Output output, const Style& style)
        : m_arch(arch)
        , m_output(output)
        , m_style(style)
    {
    }

    void walk(const LIEF::MachO::Binary& binary, const std::string& path)
    {
        std::string root = normalize(path);
        m_executableDirectory = directoryOf(root);

        if (m_output == Output::Graph) {
            std::cout << "digraph dependencies {\n  rankdir=LR;\n  node [shape=box, fontname=Menlo];\n";
            visit(binary, root, { }, "", 0);
            std::cout << "}\n";

            return;
        }

        std::cout << "  " << m_style.bold() << display(root) << m_style.reset() << " [" << m_arch << "]\n";
        visit(binary, root, { }, "  ", 0);
    }

private:
    std::string expand(std::string path, const std::string& loaderDirectory) const
    {
        if (!replacePrefix(path, "@executable_path", m_executableDirectory)) {
            replacePrefix(path, "@loader_path", loaderDirectory);
        }

        return path;
    }

    Resolution resolve(const std::string& installName, const std::string& loaderDirectory, const std::vector<RPath>& rpaths) const
    {
        Resolution resolution;
        std::string rest = installName;

        if (!replacePrefix(rest, "@rpath", "")) {
            std::string path = expand(installName, loaderDirectory);
            resolution.found = locate(path);
            resolution.path = resolution.found == Found::OnDisk ? normalize(path) : path;

            return resolution;
        }

        // dyld tries each LC_RPATH in order. Loading image's first, those
        // of the image that loaded it, up to the main executable.
        for (const RPath& rpath : rpaths) {
            std::string candidate = normalize(expand(rpath.path, rpath.loaderDirectory) + rest);
            Found found = locate(candidate);

            if (found != Found::Missing) {
                resolution.found = found;
                resolution.path = candidate;
                resolution.via = rpath.path;

                return resolution;
            }

            resolution.tried.push_back(rpath.path);
        }

        resolution.path = installName;

        return resolution;
    }

    void visit(const LIEF::MachO::Binary& binary, const std::string& path, std::vector<RPath> rpaths, const std::string& prefix, int depth)
    {
        // This image's rpaths come before the ones inherited from the
        // images that loaded it.
        std::string loaderDirectory = directoryOf(path);
        std::vector<RPath> own;

        for (const LIEF::MachO::RPathCommand& rpath : binary.rpaths()) {
            own.push_back({ rpath.path(), loaderDirectory });
        }

        rpaths.insert(rpaths.begin(), own.begin(), own.end());

        std::vector<const LIEF::MachO::DylibCommand*> libraries = loadedLibraries(binary);

        for (std::size_t i = 0; i < libraries.size(); ++i) {
            const LIEF::MachO::DylibCommand& library = *libraries[i];
            bool isLast = i + 1 == libraries.size();
            Resolution resolution = resolve(library.name(), loaderDirectory, rpaths);
            bool isFirstVisit = resolution.found == Found::OnDisk && m_visited.insert(resolution.path).second;

            // Only a library seen for the first time is read. The tree
            // shows each one's dependencies once.
            std::unique_ptr<LIEF::MachO::FatBinary> fat;
            const LIEF::MachO::Binary* slice = nullptr;

            if (isFirstVisit) {
                fat = LIEF::MachO::Parser::parse(resolution.path);
                slice = fat ? findSlice(*fat, m_arch) : nullptr;
            }

            if (m_output == Output::Graph) {
                printEdge(path, library, resolution);
            } else {
                printBranch(library, resolution, prefix + (isLast ? "`-- " : "|-- "), isFirstVisit, slice);
            }

            if (slice && depth + 1 < maximumDepth) {
                visit(*slice, resolution.path, rpaths, prefix + (isLast ? "    " : "|   "), depth + 1);
            }
        }
    }

    void printBranch(const LIEF::MachO::DylibCommand& library, const Resolution& resolution, const std::string& branch, bool isFirstVisit, const LIEF::MachO::Binary* slice) const
    {
        std::cout << branch << library.name() << kindTag(library.command());

        if (resolution.found == Found::OnDisk && resolution.path != library.name()) {
            std::cout << " -> " << display(resolution.path);
        }

        if (resolution.found == Found::InSharedCache) {
            std::cout << "  " << m_style.dim() << "[shared cache]" << m_style.reset();
        }

        if (resolution.found == Found::Missing) {
            std::cout << "  " << m_style.red() << "[not found]" << m_style.reset();
        }

        if (!resolution.via.empty()) {
            std::cout << "  " << m_style.dim() << "via " << resolution.via << m_style.reset();
        }

        for (const std::string& tried : resolution.tried) {
            std::cout << "  " << m_style.dim() << "(tried " << tried << ")" << m_style.reset();
        }

        if (resolution.found == Found::OnDisk && !isFirstVisit) {
            std::cout << "  " << m_style.dim() << "(see above)" << m_style.reset();
        }

        if (isFirstVisit && !slice) {
            std::cout << "  " << m_style.red() << "[no " << m_arch << " slice]" << m_style.reset();
        }

        std::cout << '\n';
    }

    // Shared-cache libraries are shaded, missing red, weak links dashed
    void printEdge(const std::string& path, const LIEF::MachO::DylibCommand& library, const Resolution& resolution) const
    {
        std::string from = fileNameOf(path);
        std::string to = fileNameOf(resolution.path);
        bool isWeak = library.command() == LIEF::MachO::LoadCommand::TYPE::LOAD_WEAK_DYLIB;

        std::cout << "  \"" << from << "\" -> \"" << to << "\"" << (isWeak ? " [style=dashed]" : "") << ";\n";

        if (resolution.found == Found::InSharedCache) {
            std::cout << "  \"" << to << "\" [style=filled, fillcolor=\"#e8e8e8\"];\n";
        }

        if (resolution.found == Found::Missing) {
            std::cout << "  \"" << to << "\" [color=red];\n";
        }
    }

    std::string_view m_arch;
    Output m_output;
    const Style& m_style;
    std::string m_executableDirectory;
    std::set<std::string> m_visited;
};

} // namespace

void dumpDependencies(const LIEF::MachO::Binary& binary, const std::string& path, const Style& style)
{
    printTitle(style, "Dependencies");

    DependencyWalker walker(archName(binary), DependencyWalker::Output::Tree, style);
    walker.walk(binary, path);
}

void printDependencyGraph(const LIEF::MachO::Binary& binary, const std::string& path)
{
    const Style plain(false);
    DependencyWalker walker(archName(binary), DependencyWalker::Output::Graph, plain);
    walker.walk(binary, path);
}

} // namespace madamp

// EOF