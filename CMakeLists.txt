# cmake -S . -B build -G "MinGW Makefiles"
# cmake --build build --target run_test

cmake_minimum_required(VERSION 3.25)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_COMPILER "gcc.exe")
set(CMAKE_CXX_COMPILER "g++.exe")

project(WinProcHandling_UnitTests LANGUAGES CXX)

include(CTest)

add_library(WinProcHandling STATIC
    WinProcHandling.cpp
    WinProcHandling.hpp
)

target_compile_definitions(WinProcHandling
    PRIVATE
        PSAPI_VERSION=1
)

target_link_libraries(WinProcHandling
    PRIVATE
        Psapi
)

# Catch2
set(CATCH2_SOURCE_DIR "$ENV{GIT_REPO_DIR}/Catch2")

add_subdirectory(
    "${CATCH2_SOURCE_DIR}"
    "${CMAKE_BINARY_DIR}/Catch2"
)

list(APPEND CMAKE_MODULE_PATH
    "${CATCH2_SOURCE_DIR}/extras"
)

include(Catch)

add_executable(WinProcHandling_UnitTests
    UnitTests.cpp
)

target_compile_definitions(WinProcHandling_UnitTests
    PRIVATE
        PSAPI_VERSION=1
)

target_link_libraries(WinProcHandling_UnitTests
    PRIVATE
        WinProcHandling
        Catch2::Catch2WithMain
)

catch_discover_tests(WinProcHandling_UnitTests)

add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS WinProcHandling_UnitTests
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)