cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR OR NOT TARGET tondb-scanner)
  message(FATAL_ERROR "Register mc burn after tondb-scanner, default OFF")
endif()
execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../external/ton"
  OUTPUT_VARIABLE MC_BURN_TON_REV OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE MC_BURN_GIT_STATUS)
if(NOT MC_BURN_GIT_STATUS EQUAL 0 OR NOT MC_BURN_TON_REV STREQUAL "afe8bfbba3a9a647d455504718bebd0303dd539b")
  message(FATAL_ERROR "MC burn requires pinned TON afe8bfbba3a9a647d455504718bebd0303dd539b")
endif()
set(MC_BURN_INPUT "")
foreach(path main.cpp ../tondb-scanner/src/DbScanner.cpp ../tondb-scanner/src/DbScanner.h)
  get_filename_component(absolute "${path}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  file(SHA256 "${absolute}" sha)
  string(APPEND MC_BURN_INPUT "${path}:${sha}\n")
endforeach()
string(SHA256 MC_BURN_SOURCE_SHA "${MC_BURN_INPUT}")
add_executable(ton-analytics-mc-burn main.cpp)
target_compile_features(ton-analytics-mc-burn PRIVATE cxx_std_20)
target_include_directories(ton-analytics-mc-burn PRIVATE ../tondb-scanner/src)
target_link_libraries(ton-analytics-mc-burn PRIVATE tondb-scanner validator ton_block ton_crypto git adnl dht)
add_dependencies(ton-analytics-mc-burn tlb_generate_tokens)
target_compile_definitions(ton-analytics-mc-burn PRIVATE
  MC_BURN_SOURCE_SHA="${MC_BURN_SOURCE_SHA}" MC_BURN_TON_REV="${MC_BURN_TON_REV}")

# Opt-in native fixture. It includes main.cpp with its CLI entrypoint disabled;
# not a NodeDB integration test and not run by the default build.
add_executable(ton-analytics-mc-burn-native-test EXCLUDE_FROM_ALL native.test.cpp)
target_compile_features(ton-analytics-mc-burn-native-test PRIVATE cxx_std_20)
target_include_directories(ton-analytics-mc-burn-native-test PRIVATE ../tondb-scanner/src)
target_link_libraries(ton-analytics-mc-burn-native-test PRIVATE tondb-scanner validator ton_block ton_crypto git adnl dht)
add_dependencies(ton-analytics-mc-burn-native-test tlb_generate_tokens)
target_compile_definitions(ton-analytics-mc-burn-native-test PRIVATE
  MC_BURN_SOURCE_SHA="${MC_BURN_SOURCE_SHA}" MC_BURN_TON_REV="${MC_BURN_TON_REV}")
