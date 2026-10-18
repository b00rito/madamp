# madamp

**madamp** is a Mach-O dumper and explorer for macOS, built on the
[LIEF](https://lief.re) C++ API.

It's developed alongside a blog series on Mach-O internals.

## What it does

The plan, roughly in the order the features arrive:

- **Layout:** the Mach header, load commands, segments (file vs. memory)
  and sections, linked libraries, and a hexdump of any section. Universal
  (fat) binaries are handled slice by slice.
- **Addresses and code:** translating a virtual address into segment,
  section, symbol and file offset, and disassembling a section or function
  with branch targets, stubs, GOT slots and strings annotated.
- **Linking:** imports grouped by library, exports from the exports trie,
  and every fixup (rebase or bind), decoded from its raw bytes, including
  chained fixups and arm64e pointer authentication.

## Dependencies

madamp needs the **LIEF C++ SDK, version 1.0 or later**:

- Prebuilt SDKs are on the [LIEF download page](https://lief.re/download/);
  for Apple Silicon, the `LIEF-<version>-Darwin-arm64` archive. madamp
  links LIEF statically, so it needs the SDK only at build time.
- LIEF can also be built from source
  (<https://github.com/lief-project/LIEF>).

For disassembly (`--disasm`) it also needs **Capstone 5**
(<https://www.capstone-engine.org/>). `madamp` links Capstone's static
library, `libcapstone.a` so it's needed only at build time.

madamp targets macOS, Apple clang as a C++17 compiler and CMake 3.20 or
later.

## Building madamp

### Requirements

- macOS with Xcode or the Command Line Tools (Apple clang, C++17)
- CMake 3.20 or later (`brew install cmake`)
- The LIEF C++ SDK, 1.0 or later (see Getting LIEF below)
- Capstone 5 (see Getting Capstone below)

### Getting LIEF

madamp builds against the LIEF SDK in `third_party/LIEF`, which isn't in
git. Download the SDK from <https://lief.re/download/> (on Apple Silicon:
`LIEF-<version>-Darwin-arm64.tar.gz`) and copy its `include` and `lib`
directories there:

```sh
tar -xzf LIEF-1.0.0-Darwin-arm64.tar.gz
mkdir -p third_party/LIEF
cp -R LIEF-1.0.0-Darwin-arm64/include LIEF-1.0.0-Darwin-arm64/lib \
    third_party/LIEF/
```

### Getting Capstone

madamp builds against the Capstone in `third_party/capstone`, which isn't
in git either. The simplest source is Homebrew, whose package includes the
static library; copy its headers and `libcapstone.a`:

```sh
brew install capstone
mkdir -p third_party/capstone/lib
cp -R "$(brew --prefix capstone)/include" third_party/capstone/
cp "$(brew --prefix capstone)/lib/libcapstone.a" third_party/capstone/lib/
```

[third_party/README.md](third_party/README.md) has the details for both.

### Build

```sh
cmake -B build
cmake --build build -j
```

CMake prints which SDK it uses (`-- LIEF 1.0.0: ...`), and which Capstone
(`-- Capstone 5: ...`). To use an SDK somewhere else, pass
`-DLIEF_DIR=<sdk_path>/lib/cmake/LIEF` to the first command, and for
Capstone `-DCAPSTONE_DIR=<dir>`, for example
`-DCAPSTONE_DIR=/opt/homebrew/opt/capstone`. CMake remembers these choices,
so later builds only need `cmake --build build -j`. To go back to
`third_party`, delete `build/` and configure again.

The default build type is `RelWithDebInfo`. Pass `-DCMAKE_BUILD_TYPE=Debug`
for a debug build.

## Usage

```
madamp [options] <mach-o file>
```

With no dump option, madamp dumps everything, for every slice of a fat
binary. `./build/madamp --help` lists all the options.

### Examples

```sh
# Everything, for every slice
./build/madamp /bin/ls

# Only one slice of a fat binary (arm64, arm64e, x86_64, ...)
./build/madamp --arch arm64e /bin/ls

# The Mach header and the load commands
./build/madamp -H -l --arch arm64e /bin/ls

# Segments (where each one is in the file and in memory), and sections
./build/madamp -g -s --arch arm64e /bin/ls

# Linked libraries and rpaths
./build/madamp -L --arch arm64e /bin/ls

# A hexdump of a section, by "SECT" or by "SEG,SECT"; -x is repeatable
./build/madamp -x __cstring --arch arm64e /bin/ls
./build/madamp -x __DATA_CONST,__got -x __cstring --arch arm64e /bin/ls

# Everything, plus a hexdump; -x alone shows only the hexdump
./build/madamp -a -x __cstring --arch arm64e /bin/ls

# Disassemble a section or a function by its symbol
./build/madamp -d __auth_stubs --arch arm64e /bin/ls

# Imports grouped by library, and exports
./build/madamp -S --arch arm64e /bin/ls

# With colors
./build/madamp --color /bin/ls | less -R
```

### Locating an address

`--addr VA` dumps what is at a virtual address. Prints info like its
segment and section, the symbol, import or string there, and its offset in
the slice and in the file. It takes hex (`0x...`) or decimal and is
repeatable.

```
$ ./build/madamp --addr 0x100003a84 --arch arm64e /bin/ls
...
== Address 0x100003a84 ==
  segment       __TEXT (0x100000000-0x100008000, r-x)
  section       __TEXT,__text +0x260 (REGULAR)
  slice offset  0x3a84
  file offset   0x13a84
```

`0x100003a84` is the entry point of `/bin/ls` (`-H` shows it). The file
offset is the slice offset plus `0x10000`, where the arm64e slice starts.
`/bin/ls` is stripped, so there's no symbol line. More addresses to try in
the same slice:

```sh
# A C string in __cstring
./build/madamp --addr 0x100007a40 --arch arm64e /bin/ls

# A stub that jumps to an imported function
./build/madamp --addr 0x1000073e8 --arch arm64e /bin/ls

# __bss: zero-filled memory, not data from the file
./build/madamp --addr 0x10000c0d0 --arch arm64e /bin/ls

# __PAGEZERO: reserved, with no access and no file bytes
./build/madamp --addr 0x1000 --arch arm64e /bin/ls
```

EOF
