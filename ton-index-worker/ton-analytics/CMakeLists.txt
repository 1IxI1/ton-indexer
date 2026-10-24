cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ton_analytics_runner_offline LANGUAGES CXX)
endif()

add_library(ton-analytics-progress STATIC Options.cpp Progress.cpp)
target_compile_features(ton-analytics-progress PUBLIC cxx_std_20)
target_include_directories(ton-analytics-progress PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test-ton-analytics-runner tests.cpp)
target_link_libraries(test-ton-analytics-runner PRIVATE ton-analytics-progress)
enable_testing()
add_test(NAME ton-analytics-runner-resume COMMAND test-ton-analytics-runner)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-store/cli.py")
  add_test(NAME ton-analytics-runner-spool-contract
    COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/spool_test.py)
endif()

# Root registration is owned by the chief. Standalone CMake deliberately builds
# only real offline tests; it does not produce a dummy/probe executable.
if(TARGET tondb-scanner)
  if(NOT TARGET ton-analytics-core)
    add_subdirectory(../ton-analytics-core ${CMAKE_CURRENT_BINARY_DIR}/core)
  endif()
  if(NOT TARGET ton-analytics-flow)
    add_subdirectory(../ton-analytics-flow ${CMAKE_CURRENT_BINARY_DIR}/flow)
  endif()
  option(TON_ANALYTICS_WITH_ACCOUNTS "Link optional Accounts sample adapter after its pinned-TON compatibility fixes" OFF)
  if(TON_ANALYTICS_WITH_ACCOUNTS AND NOT TARGET ton-analytics-accounts-native)
    add_subdirectory(../ton-analytics-accounts ${CMAKE_CURRENT_BINARY_DIR}/accounts)
  endif()
  # Domain directories currently expose executables rather than linkable stage
  # libraries. Compile their existing stage implementations without their mains.
  add_library(ton-analytics-runner-stages STATIC
    ../ton-analytics-validators/ValidatorCoreBridge.cpp
    ../ton-analytics-validators/ValidatorFacts.cpp
    ../tondb-scanner/src/analytics/validators/ValidatorStage.cpp
    ../tondb-scanner/src/analytics/validators/ValidatorSnapshot.cpp
    ../tondb-scanner/src/analytics/validators/ValidatorElectionObservation.cpp
    ../ton-analytics-wallets/WalletEventExtractor.cpp
    ../tondb-scanner/src/assets_analytics/NftEvents.cpp)
  target_compile_features(ton-analytics-runner-stages PUBLIC cxx_std_20)
  target_link_libraries(ton-analytics-runner-stages PUBLIC ton-analytics-core tondb-scanner validator)
  add_dependencies(ton-analytics-runner-stages tlb_generate_tokens)
  add_executable(ton-analytics main.cpp Scheduler.cpp Serialization.cpp Adapters.cpp)
  target_compile_features(ton-analytics PRIVATE cxx_std_20)
  target_link_libraries(ton-analytics PRIVATE ton-analytics-progress ton-analytics-core
    ton-analytics-flow ton-analytics-runner-stages tondb-scanner validator)
  if(TON_ANALYTICS_WITH_ACCOUNTS)
    target_link_libraries(ton-analytics PRIVATE ton-analytics-accounts-native)
    target_compile_definitions(ton-analytics PRIVATE TON_ANALYTICS_WITH_ACCOUNTS=1)
  endif()
  add_dependencies(ton-analytics tlb_generate_tokens)
  # Native-linked, offline regression: synthetic proof metadata is explicitly
  # test-only; exercises the shared bridge mapping, runner adapter and renderer.
  add_executable(test-ton-analytics-validator-adapter ValidatorAdapter.test.cpp Adapters.cpp Serialization.cpp)
  target_compile_features(test-ton-analytics-validator-adapter PRIVATE cxx_std_20)
  target_link_libraries(test-ton-analytics-validator-adapter PRIVATE ton-analytics-progress ton-analytics-core
    ton-analytics-flow ton-analytics-runner-stages tondb-scanner validator ton_block ton_crypto git adnl dht)
  add_dependencies(test-ton-analytics-validator-adapter tlb_generate_tokens)
  add_test(NAME ton-analytics-validator-adapter COMMAND test-ton-analytics-validator-adapter)
  # Source provenance includes uncommitted module code, not only the git HEAD.
  file(GLOB RUNNER_PROVENANCE_FILES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-core/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-core/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-flow/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-flow/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-accounts/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-accounts/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-wallets/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-wallets/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-validators/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics-validators/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/analytics/validators/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/analytics/validators/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/assets_analytics/NftEvents.*"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/tlb/tokens.tlb"
    "${CMAKE_CURRENT_SOURCE_DIR}/../patches/*")
  # Generated TL-B outputs cannot also be CMake configure inputs: Ninja would
  # receive both their generator rule and CMake's missing-input phony rule.
  list(FILTER RUNNER_PROVENANCE_FILES EXCLUDE REGEX "/tokens-tlb\\.(cpp|h)$")
  list(SORT RUNNER_PROVENANCE_FILES)
  set(RUNNER_SOURCE_DIGESTS "")
  foreach(source IN LISTS RUNNER_PROVENANCE_FILES)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    file(SHA256 "${source}" source_digest)
    file(RELATIVE_PATH source_name "${CMAKE_CURRENT_SOURCE_DIR}/.." "${source}")
    string(APPEND RUNNER_SOURCE_DIGESTS "${source_name}:${source_digest}\n")
  endforeach()
  string(SHA256 RUNNER_SOURCE_SHA256 "${RUNNER_SOURCE_DIGESTS}")
  execute_process(COMMAND git rev-parse HEAD
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../external/ton"
    OUTPUT_VARIABLE RUNNER_TON_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE RUNNER_TON_REVISION_RESULT)
  if(NOT RUNNER_TON_REVISION_RESULT EQUAL 0)
    message(FATAL_ERROR "Cannot pin TON source revision for analytics provenance")
  endif()
  target_compile_definitions(ton-analytics PRIVATE
    TON_ANALYTICS_SOURCE_SHA256="${RUNNER_SOURCE_SHA256}"
    TON_ANALYTICS_TON_REVISION="${RUNNER_TON_REVISION}")
endif()
