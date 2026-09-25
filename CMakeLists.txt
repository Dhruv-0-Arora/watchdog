cmake_minimum_required(VERSION 3.25)
project(watchdog VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WATCHDOG_COUNT_ALLOCATIONS "Count global allocations to assert allocation-free steady state" OFF)
option(WATCHDOG_BUILD_FUZZERS "Build libFuzzer targets (requires clang with -fsanitize=fuzzer)" OFF)

find_package(Threads REQUIRED)
find_path(PCAP_INCLUDE_DIR pcap/pcap.h REQUIRED)
find_library(PCAP_LIBRARY pcap REQUIRED)

add_library(watchdog_warnings INTERFACE)
target_compile_options(watchdog_warnings INTERFACE
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
  -Wshadow
  -Werror)

add_library(watchdog_core INTERFACE)
target_include_directories(watchdog_core INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(watchdog_core INTERFACE watchdog_warnings)

add_library(watchdog_alloc_probe OBJECT src/support/alloc_probe.cpp)
target_link_libraries(watchdog_alloc_probe PRIVATE watchdog_core)
if(WATCHDOG_COUNT_ALLOCATIONS)
  target_compile_definitions(watchdog_alloc_probe PUBLIC WATCHDOG_COUNT_ALLOCATIONS)
endif()

add_library(watchdog_platform STATIC
  src/platform/alert_log.cpp
  src/platform/capture_pcap.cpp
  src/platform/checkpoint.cpp
  src/platform/ipc.cpp
  src/platform/resources.cpp
  src/platform/paths.cpp
  src/platform/privilege.cpp
  src/platform/settings_file.cpp)
target_include_directories(watchdog_platform SYSTEM PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(watchdog_platform PUBLIC watchdog_core PRIVATE ${PCAP_LIBRARY})

add_library(watchdog_app STATIC
  src/app/pipeline.cpp
  src/app/tui.cpp)
target_link_libraries(watchdog_app PUBLIC watchdog_core watchdog_platform Threads::Threads)

add_executable(watchdog src/app/daemon.cpp)
target_link_libraries(watchdog PRIVATE watchdog_app watchdog_alloc_probe)
target_compile_definitions(watchdog PRIVATE WATCHDOG_VERSION="${PROJECT_VERSION}")

if(WATCHDOG_BUILD_FUZZERS)
  add_executable(fuzz_decode fuzz/fuzz_decode.cpp)
  target_link_libraries(fuzz_decode PRIVATE watchdog_core)
  target_compile_options(fuzz_decode PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_decode PRIVATE -fsanitize=fuzzer)
endif()

enable_testing()

add_executable(watchdog_tests
  tests/test_main.cpp
  tests/test_alloc_probe.cpp
  tests/test_ring.cpp
  tests/test_decode.cpp
  tests/test_stats.cpp
  tests/test_table.cpp
  tests/test_features.cpp
  tests/test_quantile.cpp
  tests/test_autoencoder.cpp
  tests/test_mapper.cpp
  tests/test_model.cpp
  tests/test_checkpoint.cpp
  tests/test_incident.cpp
  tests/test_alert_log.cpp
  tests/test_ipc.cpp
  tests/test_config.cpp
  tests/test_privilege.cpp)
target_link_libraries(watchdog_tests PRIVATE watchdog_core watchdog_platform watchdog_alloc_probe
                                             Threads::Threads)
target_include_directories(watchdog_tests SYSTEM PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
add_test(NAME unit COMMAND watchdog_tests)
