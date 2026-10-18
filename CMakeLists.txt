cmake_minimum_required(VERSION 3.20)
project(madamp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# The LIEF C++ SDK, linked statically. By default it comes from
# third_party/LIEF, which isn't in git (see third_party/README.md). To use
# another SDK, pass -DLIEF_DIR=<sdk>/lib/cmake/LIEF.
set(MADAMP_LIEF_SDK "${CMAKE_CURRENT_SOURCE_DIR}/third_party/LIEF")

if(NOT LIEF_DIR AND EXISTS "${MADAMP_LIEF_SDK}/lib/cmake/LIEF")
  set(LIEF_DIR "${MADAMP_LIEF_SDK}/lib/cmake/LIEF")
endif()

find_package(LIEF 1.0 COMPONENTS STATIC)

if(NOT LIEF_FOUND)
    message(FATAL_ERROR
        "LIEF SDK not found. Put it in third_party/LIEF (see "
        "third_party/README.md), or pass -DLIEF_DIR=<sdk>/lib/cmake/LIEF.")
endif()

message(STATUS "LIEF ${LIEF_VERSION}: ${LIEF_DIR}")

# Capstone 5 for disassembly, linked statically. By default it comes from
# third_party/capstone, which isn't in git (see third_party/README.md). To
# use another copy with the same layout, such as Homebrew's, pass
# -DCAPSTONE_DIR=/opt/homebrew/opt/capstone.
set(MADAMP_CAPSTONE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone")

if(NOT CAPSTONE_DIR)
  set(CAPSTONE_DIR "${MADAMP_CAPSTONE}")
endif()

set(CAPSTONE_INCLUDE_DIR "${CAPSTONE_DIR}/include/capstone")
set(CAPSTONE_LIBRARY "${CAPSTONE_DIR}/lib/libcapstone.a")

if(NOT EXISTS "${CAPSTONE_INCLUDE_DIR}/capstone.h" OR NOT EXISTS "${CAPSTONE_LIBRARY}")
    message(FATAL_ERROR
        "Capstone not found in ${CAPSTONE_DIR}. Put it in "
        "third_party/capstone (see third_party/README.md), or pass "
        "-DCAPSTONE_DIR=<dir with include/capstone and lib/libcapstone.a>.")
endif()

file(STRINGS "${CAPSTONE_INCLUDE_DIR}/capstone.h" CAPSTONE_MAJOR REGEX "^#define CS_API_MAJOR ")
string(REGEX REPLACE "^#define CS_API_MAJOR ([0-9]+).*" "\\1" CAPSTONE_MAJOR "${CAPSTONE_MAJOR}")

if(CAPSTONE_MAJOR LESS 5)
    message(FATAL_ERROR "Capstone ${CAPSTONE_MAJOR} in ${CAPSTONE_DIR}; madamp needs 5 or later.")
endif()

message(STATUS "Capstone ${CAPSTONE_MAJOR}: ${CAPSTONE_DIR}")

add_executable(madamp
    src/main.cpp
    src/Architecture.cpp
    src/Dump.cpp
    src/Error.cpp
    src/Format.cpp
    src/Options.cpp
    src/HeaderDump.cpp
    src/LoadCommandsDump.cpp
    src/SegmentsDump.cpp
    src/SectionsDump.cpp
    src/LibrariesDump.cpp
    src/HexDump.cpp
    src/MachOUtilities.cpp
    src/AddressMap.cpp
    src/AddressDump.cpp
    src/DisassemblyDump.cpp
    src/SymbolsDump.cpp
    src/ChainedFixups.cpp
    src/FixupsDump.cpp
)
target_include_directories(madamp SYSTEM PRIVATE ${CAPSTONE_INCLUDE_DIR})
target_link_libraries(madamp PRIVATE LIEF::LIEF ${CAPSTONE_LIBRARY})
target_compile_options(madamp PRIVATE -Wall -Wextra -Wpedantic)

# EOF