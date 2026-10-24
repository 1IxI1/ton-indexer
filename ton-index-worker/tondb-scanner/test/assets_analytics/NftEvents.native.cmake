# Chief/single-builder hook, included from the matching indexer build AFTER
# add_subdirectory(tondb-scanner). No shared CMake file is changed by this fix:
# include("${CMAKE_CURRENT_SOURCE_DIR}/tondb-scanner/test/assets_analytics/NftEvents.native.cmake")
# cmake --build <build> --target test-nft-events-native
# ctest --test-dir <build> -R '^nft-events-native$' --output-on-failure
include_guard(GLOBAL)
if(NOT TARGET tondb-scanner OR NOT TARGET tlb_generate_tokens OR NOT TARGET tlb_generate_block)
  message(FATAL_ERROR "NFT native fixture requires the indexer's generated TON/scanner targets")
endif()
find_package(Git REQUIRED)
execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
  WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/../../../external/ton"
  OUTPUT_VARIABLE NFT_FIXTURE_TON_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE NFT_FIXTURE_GIT_RESULT ERROR_QUIET)
if(NOT NFT_FIXTURE_GIT_RESULT EQUAL 0 OR
   NOT NFT_FIXTURE_TON_HEAD STREQUAL "afe8bfbba3a9a647d455504718bebd0303dd539b")
  message(FATAL_ERROR "NFT native fixture requires pinned TON afe8bfb, not borrowed generated headers")
endif()
add_executable(test-nft-events-native
  "${CMAKE_CURRENT_LIST_DIR}/NftEvents.native.test.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/../../src/assets_analytics/NftEvents.cpp")
target_compile_features(test-nft-events-native PRIVATE cxx_std_20)
target_link_libraries(test-nft-events-native PRIVATE tondb-scanner validator ton_block ton_crypto git adnl dht)
add_dependencies(test-nft-events-native tlb_generate_tokens tlb_generate_block)
enable_testing()
add_test(NAME nft-events-native COMMAND test-nft-events-native)
set_tests_properties(nft-events-native PROPERTIES TIMEOUT 60)
