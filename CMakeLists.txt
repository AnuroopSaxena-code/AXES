cmake_minimum_required(VERSION 3.14)
project(AXES VERSION 0.3.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -pedantic -pthread)
endif()

# Include directories
include_directories(src)

# Core AXES sources
set(AXES_SOURCES
    src/cgroup.cpp
    src/cgroup.hpp
    src/monitor.cpp
    src/monitor.hpp
    src/launcher.cpp
    src/launcher.hpp
)

# Main Executable
add_executable(axes src/main.cpp ${AXES_SOURCES})
target_link_libraries(axes PRIVATE pthread)

# Test Suite Executable
add_executable(test_axes tests/test_suite.cpp ${AXES_SOURCES})
target_link_libraries(test_axes PRIVATE pthread)

# Build C process stress workload binary
add_executable(process_stress workloads/process_stress.c)

# Custom target to ensure reports directory exists
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/reports)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/reports)
