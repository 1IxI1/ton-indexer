cmake_minimum_required(VERSION 3.16)

project(ton-index-cpp)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(PGTON "Enable adding the pgton subdirectory" OFF)
option(TON_USE_JEMALLOC "Use \"ON\" to enable JeMalloc." OFF)
option(TON_INDEXER_ANALYTICS "Build the opt-in existing IndexScheduler analytics stage/replay" OFF)

# Find jemalloc
if (TON_USE_JEMALLOC)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/external/ton/CMake")
    find_package(jemalloc REQUIRED)

    if (JEMALLOC_FOUND)
        include_directories(${JEMALLOC_INCLUDE_DIR})
        link_libraries(${JEMALLOC_LIBRARIES})
        add_compile_definitions(TON_USE_JEMALLOC)
    endif()
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
add_subdirectory(external/ton EXCLUDE_FROM_ALL)
add_subdirectory(external/libpqxx EXCLUDE_FROM_ALL)

find_package(Git REQUIRED)
set(TON_INDEXER_ROCKSDB_SECONDARY_OPEN_PATCH
    ${CMAKE_CURRENT_SOURCE_DIR}/patches/fix-secondary-open.patch)
add_custom_target(apply-rocksdb-secondary-open-patch
  COMMAND ${CMAKE_COMMAND}
    -DGIT_EXECUTABLE=${GIT_EXECUTABLE}
    -DPATCH_FILE=${TON_INDEXER_ROCKSDB_SECONDARY_OPEN_PATCH}
    -DPATCH_WORKING_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/external/ton/third-party/rocksdb
    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ApplyPatch.cmake
  VERBATIM
)
add_dependencies(rocksdb apply-rocksdb-secondary-open-patch)


# The TON subtree already provides an lz4 target.  Tell clickhouse-cpp to use
# that configured library instead of adding its bundled target with the same
# plain name.
set(WITH_SYSTEM_LZ4 ON CACHE BOOL "Use configured LZ4 for clickhouse-cpp" FORCE)
set(WITH_SYSTEM_ABSEIL ON CACHE BOOL "Use configured Abseil for clickhouse-cpp" FORCE)
if (TARGET absl::int128)
    # clickhouse-cpp calls find_package(absl); route it to TON's in-tree Abseil
    # targets instead of importing a second system Abseil package.
    set(absl_DIR "${CMAKE_CURRENT_LIST_DIR}/cmake/absl" CACHE PATH "Use TON-provided Abseil targets for clickhouse-cpp" FORCE)
endif()
add_subdirectory(external/clickhouse-cpp EXCLUDE_FROM_ALL)
set(REDIS_PLUS_PLUS_BUILD_TEST OFF CACHE BOOL "disable test" FORCE)

# workaround to link static libhiredis
set(TON_INDEXER_CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
find_library(TON_INDEXER_HIREDIS_STATIC_LIB hiredis REQUIRED)
set(CMAKE_FIND_LIBRARY_SUFFIXES ${TON_INDEXER_CMAKE_FIND_LIBRARY_SUFFIXES})
unset(TON_INDEXER_CMAKE_FIND_LIBRARY_SUFFIXES)
set(HIREDIS_LIB "${TON_INDEXER_HIREDIS_STATIC_LIB}" CACHE FILEPATH "hiredis static library" FORCE)
set(REDIS_PLUS_PLUS_BUILD_SHARED OFF CACHE BOOL "disable shared redis++" FORCE)
add_subdirectory(external/redis-plus-plus EXCLUDE_FROM_ALL)
target_link_libraries(redis++_static PUBLIC ${TON_INDEXER_HIREDIS_STATIC_LIB})

set(MSGPACK_USE_BOOST OFF CACHE BOOL "disable boost" FORCE)
set(MSGPACK_USE_STD_VARIANT_ADAPTOR ON CACHE BOOL "enable std::variant" FORCE)
add_subdirectory(external/msgpack-c EXCLUDE_FROM_ALL)

function(add_ton_indexer_opentelemetry_cpp)
    set(BUILD_TESTING OFF)
    set(WITH_BENCHMARK OFF)
    set(WITH_EXAMPLES OFF)
    set(WITH_EXAMPLES_HTTP OFF)
    set(WITH_FUNC_TESTS OFF)
    set(WITH_OTLP_GRPC OFF)
    set(WITH_OTLP_HTTP ON)
    set(WITH_OTLP_FILE OFF)
    set(WITH_PROMETHEUS OFF)
    set(WITH_ZIPKIN OFF)
    set(WITH_ELASTICSEARCH OFF)
    set(OPENTELEMETRY_INSTALL OFF)
    set(Protobuf_USE_STATIC_LIBS ON CACHE BOOL "Prefer static protobuf libraries" FORCE)
    add_subdirectory(external/opentelemetry-cpp EXCLUDE_FROM_ALL)
endfunction()

add_ton_indexer_opentelemetry_cpp()

add_subdirectory(tondb-scanner)
option(TON_ANALYTICS_MC_BURN "Build standalone read-only archived MC burn reader" OFF)
if(TON_ANALYTICS_MC_BURN)
    add_subdirectory(ton-analytics-mc-burn EXCLUDE_FROM_ALL)
endif()
option(TON_ANALYTICS_NFT_NATIVE_TEST "Build pinned-TON NFT raw-message regression fixture" OFF)
if(TON_ANALYTICS_NFT_NATIVE_TEST)
    include("${CMAKE_CURRENT_SOURCE_DIR}/tondb-scanner/test/assets_analytics/NftEvents.native.cmake")
endif()
add_subdirectory(ton-analytics-core EXCLUDE_FROM_ALL)
add_subdirectory(ton-analytics EXCLUDE_FROM_ALL)
option(TON_ANALYTICS_MONTH_FLOW "Build standalone opt-in raw monthly flow producer" OFF)
if(TON_ANALYTICS_MONTH_FLOW)
    add_subdirectory(ton-analytics-month-flow EXCLUDE_FROM_ALL)
endif()
add_subdirectory(ton-analytics-validators EXCLUDE_FROM_ALL)
add_subdirectory(ton-analytics-wallets EXCLUDE_FROM_ALL)
add_subdirectory(ton-analytics-assets EXCLUDE_FROM_ALL)
add_subdirectory(ton-kvrocks-state)
add_subdirectory(ton-marker)
add_subdirectory(ton-observability)
if(TON_INDEXER_ANALYTICS)
    add_subdirectory(ton-analytics-pipeline)
endif()
add_subdirectory(ton-index-postgres)
add_subdirectory(ton-index-clickhouse)
add_subdirectory(ton-integrity-checker)
add_subdirectory(ton-analytics-gram EXCLUDE_FROM_ALL)

# Native analytics links the validator OBJECT target directly. Supply its Git
# metadata and explicit block/VM and ADNL/DHT static-library ordering.
set(TON_ANALYTICS_NATIVE_TARGETS
    ton-analytics ton-analytics-gram ton-analytics-validators ton-analytics-assets
    ton-analytics-assets-events-native ton-analytics-wallets-events)
if (TON_WALLETS_TON_ADAPTER_AVAILABLE)
    list(APPEND TON_ANALYTICS_NATIVE_TARGETS ton-analytics-wallets
        test-ton-analytics-wallets-extractor test-ton-analytics-wallets-stage
        test-ton-analytics-wallets-raw-inventory)
endif()
foreach(analytics_native_target IN LISTS TON_ANALYTICS_NATIVE_TARGETS)
    if (TARGET ${analytics_native_target})
        target_link_libraries(${analytics_native_target} PUBLIC ton_block ton_crypto git adnl dht)
    endif()
endforeach()

add_subdirectory(ton-smc-scanner)
add_subdirectory(ton-trace-emulator)
add_subdirectory(ton-trace-task-emulator)
add_subdirectory(celldb-migrate)
add_subdirectory(index-engine)

if (PGTON)
    message("Building pgton")
    add_subdirectory(pgton)
endif()
