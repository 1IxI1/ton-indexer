# The parent registers these explicit analytics targets with EXCLUDE_FROM_ALL.
add_library(ton-analytics-core STATIC AnchorEvidence.cpp Relationships.cpp)
target_compile_features(ton-analytics-core PUBLIC cxx_std_20)
target_include_directories(ton-analytics-core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src)
target_link_libraries(ton-analytics-core PUBLIC ton_block ton_crypto tdutils)
add_dependencies(ton-analytics-core tlb_generate_tokens)

add_executable(test-ton-analytics-core AnchorEvidence.test.cpp Relationships.cpp)
target_compile_features(test-ton-analytics-core PRIVATE cxx_std_20)
target_link_libraries(test-ton-analytics-core PRIVATE ton_crypto_core tdutils)
add_executable(test-ton-analytics-core-native NativeEntry.test.cpp)
target_compile_features(test-ton-analytics-core-native PRIVATE cxx_std_20)
target_link_libraries(test-ton-analytics-core-native PRIVATE ton-analytics-core)
enable_testing()
add_test(NAME ton-analytics-core-synthetic COMMAND test-ton-analytics-core)
add_test(NAME ton-analytics-core-native-entry COMMAND test-ton-analytics-core-native)
