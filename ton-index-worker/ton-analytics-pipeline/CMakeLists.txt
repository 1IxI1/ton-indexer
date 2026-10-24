cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ton_analytics_pipeline_offline LANGUAGES CXX)
endif()

add_library(ton-analytics-pipeline-spool STATIC Spool.cpp)
target_compile_features(ton-analytics-pipeline-spool PUBLIC cxx_std_20)
target_include_directories(ton-analytics-pipeline-spool PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
enable_testing()
add_executable(test-ton-analytics-pipeline-spool Spool.test.cpp)
target_link_libraries(test-ton-analytics-pipeline-spool PRIVATE ton-analytics-pipeline-spool)
add_test(NAME ton-analytics-pipeline-spool COMMAND test-ton-analytics-pipeline-spool)

if(TARGET tondb-scanner)
  add_library(ton-analytics-pipeline STATIC Processor.cpp
    ../ton-analytics/Serialization.cpp ../ton-analytics/Adapters.cpp
    ../ton-analytics-wallets/WalletStage.cpp ../ton-analytics-wallets/WalletRawInventory.cpp
    ../tondb-scanner/src/assets_analytics/Extractor.cpp)
  target_compile_features(ton-analytics-pipeline PUBLIC cxx_std_20)
  target_include_directories(ton-analytics-pipeline PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../index-engine/src)
  # runner-stages is the sole NftEvents/WalletEventExtractor object owner in this
  # link. Do not also link assets-events-native or wallets-events here.
  target_link_libraries(ton-analytics-pipeline PUBLIC ton-analytics-pipeline-spool
    ton-analytics-progress ton-analytics-core ton-analytics-flow
    ton-analytics-runner-stages ton-analytics-wallets-metrics ton-analytics-assets-facts
    tondb-scanner validator ton_block ton_crypto git adnl dht)
  add_dependencies(ton-analytics-pipeline tlb_generate_tokens tlb_generate_block)

  file(GLOB_RECURSE PIPELINE_PROVENANCE CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../index-engine/src/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../index-engine/src/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-index-clickhouse/src/main.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics*/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics*/*.h")
  # Glob patterns don't expand directory wildcards recursively on all CMake
  # versions. Include the existing runner's dependency digest as well.
  file(GLOB PIPELINE_MODULES "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics*")
  foreach(module IN LISTS PIPELINE_MODULES)
    file(GLOB_RECURSE module_sources CONFIGURE_DEPENDS "${module}/*.cpp" "${module}/*.h")
    list(APPEND PIPELINE_PROVENANCE ${module_sources})
  endforeach()
  file(GLOB_RECURSE PIPELINE_SCANNER CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src/*.h")
  list(APPEND PIPELINE_PROVENANCE ${PIPELINE_SCANNER})
  list(FILTER PIPELINE_PROVENANCE EXCLUDE REGEX "/tokens-tlb\\.(cpp|h)$")
  set(normalized_sources "")
  foreach(source IN LISTS PIPELINE_PROVENANCE)
    get_filename_component(source "${source}" REALPATH)
    list(APPEND normalized_sources "${source}")
  endforeach()
  set(PIPELINE_PROVENANCE ${normalized_sources})
  list(REMOVE_DUPLICATES PIPELINE_PROVENANCE)
  list(SORT PIPELINE_PROVENANCE)
  # CMake 3.22 emits duplicate Ninja phony outputs for syntactically different
  # paths naming one configure input. Existing runner deps already watch shared
  # sources; don't register their normalized spelling a second time here.
  get_filename_component(runner_directory "${CMAKE_CURRENT_SOURCE_DIR}/../ton-analytics" REALPATH)
  get_property(runner_inputs DIRECTORY "${runner_directory}" PROPERTY CMAKE_CONFIGURE_DEPENDS)
  set(watched "")
  foreach(source IN LISTS runner_inputs)
    get_filename_component(source "${source}" REALPATH)
    list(APPEND watched "${source}")
  endforeach()
  set(PIPELINE_DIGESTS "")
  foreach(source IN LISTS PIPELINE_PROVENANCE)
    if(NOT source IN_LIST watched)
      set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${source}")
    endif()
    file(SHA256 "${source}" source_digest)
    file(RELATIVE_PATH source_name "${CMAKE_CURRENT_SOURCE_DIR}/.." "${source}")
    string(APPEND PIPELINE_DIGESTS "${source_name}:${source_digest}\n")
  endforeach()
  string(SHA256 PIPELINE_SOURCE_SHA256 "${PIPELINE_DIGESTS}")
  execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../external/ton"
    OUTPUT_VARIABLE PIPELINE_TON_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
  target_compile_definitions(ton-analytics-pipeline PRIVATE
    TON_ANALYTICS_SOURCE_SHA256="${PIPELINE_SOURCE_SHA256}"
    TON_ANALYTICS_TON_REVISION="${PIPELINE_TON_REVISION}")
  add_executable(test-ton-analytics-pipeline-native Pipeline.test.cpp)
  target_link_libraries(test-ton-analytics-pipeline-native PRIVATE ton-analytics-pipeline index-engine-core)
  add_dependencies(test-ton-analytics-pipeline-native tlb_generate_tokens tlb_generate_block)
  add_test(NAME ton-analytics-pipeline-native COMMAND test-ton-analytics-pipeline-native)
  set_tests_properties(ton-analytics-pipeline-native PROPERTIES TIMEOUT 60)
  find_package(Python3 COMPONENTS Interpreter QUIET)
  if(Python3_Interpreter_FOUND)
    add_test(NAME ton-analytics-pipeline-wire
      COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/Wire.test.py $<TARGET_FILE:test-ton-analytics-pipeline-native>)
  endif()
endif()
