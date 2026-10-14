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

add_executable(madamp
    src/main.cpp
    src/Architecture.cpp
    src/Dump.cpp
    src/Error.cpp
    src/Format.cpp
    src/Options.cpp
    src/HeaderDump.cpp
    src/LoadCommandsDump.cpp
)
target_link_libraries(madamp PRIVATE LIEF::LIEF)
target_compile_options(madamp PRIVATE -Wall -Wextra -Wpedantic)

# EOF
