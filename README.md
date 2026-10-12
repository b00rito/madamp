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

EOF
