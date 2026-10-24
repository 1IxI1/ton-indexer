cmake_minimum_required(VERSION 3.16)
project(ton_analytics_accounts LANGUAGES CXX)

add_library(ton-analytics-accounts-model INTERFACE)
target_include_directories(ton-analytics-accounts-model INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(ton-analytics-accounts-model INTERFACE cxx_std_20)

add_executable(test-ton-analytics-accounts test.cpp)
target_link_libraries(test-ton-analytics-accounts PRIVATE ton-analytics-accounts-model)
enable_testing()
add_test(NAME ton-analytics-accounts-fixture COMMAND test-ton-analytics-accounts)

# Optional native adapter when included by the TON index-worker build. Its
# parent must add_subdirectory(ton-analytics-accounts) after tondb-scanner;
# this module intentionally does NOT modify the parent's CMake or scheduler.
if(TARGET tondb-scanner AND TARGET validator)
  add_library(ton-analytics-accounts-native STATIC Native.cpp)
  target_include_directories(ton-analytics-accounts-native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../tondb-scanner/src)
  target_link_libraries(ton-analytics-accounts-native PUBLIC
    ton-analytics-accounts-model tondb-scanner validator)
endif()
