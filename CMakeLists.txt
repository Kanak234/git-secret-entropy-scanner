cmake_minimum_required(VERSION 3.22)
project(git_secret_entropy_scanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(ENABLE_COVERAGE "Enable code coverage instrumentation" OFF)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wshadow -Wnon-virtual-dtor
        -O3
    )
endif()

if (ENABLE_COVERAGE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

find_package(Threads REQUIRED)

# Core Library
add_library(scanner_core
    src/EntropyCalculator.cpp
    src/RuleEngine.cpp
    src/FalsePositiveFilter.cpp
    src/Scanner.cpp
    src/GitLogParser.cpp
    src/DirectoryWalker.cpp
    src/Reporter.cpp
    src/ThreadPool.cpp
)

target_include_directories(scanner_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(scanner_core PUBLIC Threads::Threads)

# CLI Application
add_executable(secret_scanner_cli src/cli/Main.cpp)
target_link_libraries(secret_scanner_cli PRIVATE scanner_core)

# Tests
enable_testing()

add_executable(test_entropy tests/TestEntropy.cpp)
target_link_libraries(test_entropy PRIVATE scanner_core)
add_test(NAME TestEntropy COMMAND test_entropy)

add_executable(test_rules tests/TestRules.cpp)
target_link_libraries(test_rules PRIVATE scanner_core)
add_test(NAME TestRules COMMAND test_rules)

add_executable(test_false_positives tests/TestFalsePositives.cpp)
target_link_libraries(test_false_positives PRIVATE scanner_core)
add_test(NAME TestFalsePositives COMMAND test_false_positives)

add_executable(test_git_scan tests/TestGitScan.cpp)
target_link_libraries(test_git_scan PRIVATE scanner_core)
add_test(NAME TestGitScan COMMAND test_git_scan)

add_executable(test_coverage_edge_cases tests/TestCoverageEdgeCases.cpp)
target_link_libraries(test_coverage_edge_cases PRIVATE scanner_core)
add_test(NAME TestCoverageEdgeCases COMMAND test_coverage_edge_cases)
