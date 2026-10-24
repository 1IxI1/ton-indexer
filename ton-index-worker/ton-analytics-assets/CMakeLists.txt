cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ton_analytics_assets_offline LANGUAGES CXX)
endif()

# These three tests have no TON headers, generated code, NodeDB, or network dependency.
add_library(ton-analytics-assets-facts STATIC AssetFacts.cpp)
target_compile_features(ton-analytics-assets-facts PUBLIC cxx_std_17)
add_executable(test-ton-analytics-assets-cli cli_test.cpp)
target_compile_features(test-ton-analytics-assets-cli PRIVATE cxx_std_17)
add_executable(test-ton-analytics-assets-facts facts_test.cpp)
target_link_libraries(test-ton-analytics-assets-facts PRIVATE ton-analytics-assets-facts)
add_executable(test-ton-analytics-assets-events event_stage_test.cpp)
target_compile_features(test-ton-analytics-assets-events PRIVATE cxx_std_20)
enable_testing()
add_test(NAME ton-analytics-assets-cli COMMAND test-ton-analytics-assets-cli)
add_test(NAME ton-analytics-assets-facts COMMAND test-ton-analytics-assets-facts)
add_test(NAME ton-analytics-assets-events COMMAND test-ton-analytics-assets-events)

# The native targets exist only when registered under the matching pinned TON
# indexer tree. Running standalone CMake never fabricates an archive-ready binary.
if(TARGET tondb-scanner)
  find_package(Git REQUIRED)
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../external/ton
    OUTPUT_VARIABLE TON_ASSETS_TON_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE TON_ASSETS_GIT_RESULT ERROR_QUIET)
  if(NOT TON_ASSETS_GIT_RESULT EQUAL 0 OR
     NOT TON_ASSETS_TON_HEAD STREQUAL "afe8bfbba3a9a647d455504718bebd0303dd539b")
    message(FATAL_ERROR "Assets native targets require pinned external/ton HEAD afe8bfb")
  endif()
  if(NOT TARGET ton-analytics-core OR NOT TARGET tlb_generate_tokens OR NOT TARGET tlb_generate_block)
    message(FATAL_ERROR "Assets native targets require ton-analytics-core, scanner tokens TL-B and pinned TON block TL-B targets")
  endif()

  option(TON_ASSETS_SECONDARY_SAFETY_REVIEWED
    "Enable Assets secondary NodeDB open ONLY after independent review" OFF)
  add_executable(ton-analytics-assets main.cpp
    ../tondb-scanner/src/assets_analytics/Extractor.cpp)
  target_compile_features(ton-analytics-assets PRIVATE cxx_std_20)
  target_link_libraries(ton-analytics-assets PRIVATE
    ton-analytics-assets-facts tondb-scanner validator)
  add_dependencies(ton-analytics-assets tlb_generate_tokens tlb_generate_block)
  if(TON_ASSETS_SECONDARY_SAFETY_REVIEWED)
    target_compile_definitions(ton-analytics-assets PRIVATE TON_ASSETS_SECONDARY_SAFETY_REVIEWED=1)
  endif()

  # Separate candidate-only adapter for the chief-owned unified runner. It is
  # not invoked by the address-subset executable or by any synthetic test.
  add_library(ton-analytics-assets-events-native STATIC AssetEventStage.cpp
    ../tondb-scanner/src/assets_analytics/NftEvents.cpp
    ../tondb-scanner/src/assets_analytics/DnsAuctionEvents.cpp)
  target_compile_features(ton-analytics-assets-events-native PUBLIC cxx_std_20)
  target_include_directories(ton-analytics-assets-events-native PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(ton-analytics-assets-events-native PUBLIC
    ton-analytics-core tondb-scanner validator)
  add_dependencies(ton-analytics-assets-events-native tlb_generate_tokens tlb_generate_block)
endif()
