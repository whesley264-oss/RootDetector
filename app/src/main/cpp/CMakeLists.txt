# CMakeLists.txt - CMake build configuration for RootDetector native library
#
# This file configures the native C++ code to be built as a shared library
# and linked with the Android NDK.

cmake_minimum_required(VERSION 3.22.1)

# Project name
project("rootdetector")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compilation flags
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
)

# Source files
set(NATIVE_SOURCES
    RootDetector.cpp
    JNI.cpp
)

# Create shared library
add_library(
    ${CMAKE_PROJECT_NAME}
    SHARED
    ${NATIVE_SOURCES}
)

# Find and link the Android log library
find_library(
    log-lib
    log
)

target_link_libraries(
    ${CMAKE_PROJECT_NAME}
    ${log-lib}
)

# Optional: Enable verbose makefile output for debugging
# set(CMAKE_VERBOSE_MAKEFILE ON)
