# Opt-in only: add_subdirectory(ton-analytics-flow) from an indexer build that
# already defines ton_block and tondb-scanner. Nothing is wired to production.
add_library(ton-analytics-flow STATIC Extractor.cpp)
target_compile_features(ton-analytics-flow PUBLIC cxx_std_20)
target_include_directories(ton-analytics-flow PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ton-analytics-flow PUBLIC tondb-scanner ton_block)

add_executable(test-ton-analytics-flow EXCLUDE_FROM_ALL test.cpp)
target_link_libraries(test-ton-analytics-flow PRIVATE ton-analytics-flow)
add_test(NAME test-ton-analytics-flow COMMAND test-ton-analytics-flow)
