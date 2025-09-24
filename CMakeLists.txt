# Tell CMake to prefer static libraries over shared ones.
set(BUILD_SHARED_LIBS OFF)

# Change the default suffixes that CMake looks for when using find_library.
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".lib")

cmake_minimum_required(VERSION 3.15)
project(z3ds_compressor)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Use a specific pkg-config call to force static linking for ZSTD
# The original call would ignore BUILD_SHARED_LIBS
set(ENV{PKG_CONFIG_EXECUTABLE} "pkg-config --static")
pkg_check_modules(ZSTD REQUIRED libzstd)
unset(ENV{PKG_CONFIG_EXECUTABLE})

# Add executable
add_executable(z3ds_compressor
    src/main.cpp
    src/z3ds_compression.cpp
)

# Link libraries, including static ZSTD dependencies
target_link_libraries(z3ds_compressor 
    PRIVATE
        ${ZSTD_LIBRARIES}
)

# Include directories
target_include_directories(z3ds_compressor PRIVATE 
    ${ZSTD_INCLUDE_DIRS}
)

# Compiler flags
target_compile_options(z3ds_compressor PRIVATE 
    ${ZSTD_CFLAGS_OTHER}
    -Wall -Wextra
)

# Installation
install(TARGETS z3ds_compressor DESTINATION bin)
