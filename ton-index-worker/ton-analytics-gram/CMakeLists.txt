add_executable(ton-analytics-gram main.cpp)
target_compile_features(ton-analytics-gram PRIVATE cxx_std_20)
# The read-only calculator is compiled into the TON validator OBJECT target.
target_link_libraries(ton-analytics-gram PRIVATE tondb-scanner validator)

add_executable(test-ton-analytics-gram test.cpp)
target_compile_features(test-ton-analytics-gram PRIVATE cxx_std_20)
target_link_libraries(test-ton-analytics-gram PRIVATE ton_crypto_core)
enable_testing()
add_test(NAME ton-analytics-gram-invariant COMMAND test-ton-analytics-gram)
