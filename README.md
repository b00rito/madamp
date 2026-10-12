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

madamp targets macOS, Apple clang as a C++17 compiler and CMake 3.20 or
later.

## Building madamp

### Requirements

- macOS with Xcode or the Command Line Tools (Apple clang, C++17)
- CMake 3.20 or later (`brew install cmake`)
- The LIEF C++ SDK, 1.0 or later (see Getting LIEF below)

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

[third_party/README.md](third_party/README.md) has the details.

### Build

```sh
cmake -B build
cmake --build build -j
```

CMake prints which SDK it uses (`-- LIEF 1.0.0: ...`). To use an SDK
somewhere else, pass `-DLIEF_DIR=<sdk_path>/lib/cmake/LIEF` to the first
command. CMake remembers the choice, so later builds only need
`cmake --build build -j`. To go back to `third_party/LIEF`, delete
`build/` and configure again.

The default build type is `RelWithDebInfo`. Pass
`-DCMAKE_BUILD_TYPE=Debug` for a debug build.

### Run

```sh
./build/madamp /bin/ls
```

EOF
