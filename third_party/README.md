# third_party

Dependencies that madamp builds against but doesn't keep in git. Only
this README is tracked; everything else here is ignored (see
`.gitignore`).

## LIEF

The LIEF C++ SDK goes in `third_party/LIEF`, with this layout:

```
third_party/LIEF/
  include/LIEF/...         headers
  lib/libLIEF.a            static library (what madamp links)
  lib/cmake/LIEF/          CMake package, found automatically
```

To set it up, download the SDK for your machine from
<https://lief.re/download/> (on Apple Silicon:
`LIEF-<version>-Darwin-arm64.tar.gz`) and copy its `include` and `lib`
directories here:

```sh
tar -xzf LIEF-1.0.0-Darwin-arm64.tar.gz
mkdir -p third_party/LIEF
cp -R LIEF-1.0.0-Darwin-arm64/include LIEF-1.0.0-Darwin-arm64/lib \
    third_party/LIEF/
```

The SDK's `bin` and `share` directories only hold examples; madamp doesn't
need them.

To use an SDK somewhere else instead, pass its CMake package directory:
`cmake -B build -DLIEF_DIR=<sdk_path>/lib/cmake/LIEF`.

EOF
