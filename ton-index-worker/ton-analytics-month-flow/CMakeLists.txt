cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  message(FATAL_ERROR "Register from ton-index-worker after tondb-scanner, ton-analytics-core and ton-analytics-flow")
endif()
if(NOT TARGET tondb-scanner OR NOT TARGET ton-analytics-core OR NOT TARGET ton-analytics-flow)
  message(FATAL_ERROR "month flow requires scanner, core and flow targets")
endif()
add_executable(ton-analytics-month-flow main.cpp ../ton-analytics/Options.cpp)
target_compile_features(ton-analytics-month-flow PRIVATE cxx_std_20)
target_include_directories(ton-analytics-month-flow PRIVATE ../ton-analytics ../tondb-scanner/src)
target_link_libraries(ton-analytics-month-flow PRIVATE ton-analytics-core ton-analytics-flow tondb-scanner validator ton_block ton_crypto git adnl dht)
add_dependencies(ton-analytics-month-flow tlb_generate_tokens)
set(FLOW_SOURCES main.cpp ../ton-analytics-flow/Extractor.cpp ../ton-analytics-core/AnchorEvidence.cpp
    ../ton-analytics-core/Relationships.cpp ../tondb-scanner/src/DbScanner.cpp)
set(FLOW_DIGEST_INPUT "")
foreach(source IN LISTS FLOW_SOURCES)
  get_filename_component(source_path "${source}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
  # The runner already tracks some of these sources as configure inputs.
  # Registering them twice creates conflicting Ninja phony rules. Explicitly
  # reconfigure the isolated build before recording a new source fingerprint.
  file(SHA256 "${source_path}" source_hash)
  string(APPEND FLOW_DIGEST_INPUT "${source}:${source_hash}\n")
endforeach()
string(SHA256 FLOW_SOURCE_SHA256 "${FLOW_DIGEST_INPUT}")
execute_process(COMMAND git rev-parse HEAD
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../external/ton"
  OUTPUT_VARIABLE FLOW_TON_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE RESULT_VARIABLE FLOW_GIT_RESULT)
if(NOT FLOW_GIT_RESULT EQUAL 0 OR NOT FLOW_TON_REVISION STREQUAL "afe8bfbba3a9a647d455504718bebd0303dd539b")
  message(FATAL_ERROR "Month flow requires pinned TON afe8bfbba3a9a647d455504718bebd0303dd539b")
endif()
target_compile_definitions(ton-analytics-month-flow PRIVATE
  FLOW_SOURCE_SHA256="${FLOW_SOURCE_SHA256}" FLOW_TON_REVISION="${FLOW_TON_REVISION}")
