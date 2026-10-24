# Standalone OFFLINE build: cmake -S ton-analytics-wallets -B <build>.
# Intentionally NOT added to the indexer's root CMake. The TON adapter must
# additionally be selected in an indexer build containing tondb-scanner.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.16)
  project(ton_analytics_wallets LANGUAGES CXX)
endif()

option(TON_WALLETS_SECONDARY_SAFETY_REVIEWED
  "Allow secondary NodeDB access only AFTER independent safety review" OFF)
option(TON_WALLETS_TON_ADAPTER_AVAILABLE
  "Compile indexer-specific TON secondary/ParseQuery adapter (requires indexer targets)" OFF)

add_executable(ton-analytics-wallets WalletPilot.cpp)
target_compile_features(ton-analytics-wallets PRIVATE cxx_std_20)

# Pure-STL reducer: one definition shared by the offline test and native stage.
add_library(ton-analytics-wallets-metrics STATIC WalletMetrics.cpp)
target_compile_features(ton-analytics-wallets-metrics PUBLIC cxx_std_20)

if(TON_WALLETS_SECONDARY_SAFETY_REVIEWED)
  target_compile_definitions(ton-analytics-wallets PRIVATE TON_WALLETS_SECONDARY_SAFETY_REVIEWED=1)
endif()
if(TON_WALLETS_TON_ADAPTER_AVAILABLE)
  if(NOT TARGET tondb-scanner OR NOT TARGET validator)
    message(FATAL_ERROR "Wallets TON adapter requires the indexer/TON target graph; no primary/readonly fallback")
  endif()

  # One compiled owner per native implementation. Runtime stage verification
  # requires a separately checked raw transaction/message inventory, never a
  # reconstruction from the extractor's events::Batch or a two-MC baseline.
  add_library(ton-analytics-wallets-events STATIC WalletEventExtractor.cpp)
  target_compile_features(ton-analytics-wallets-events PUBLIC cxx_std_20)
  target_include_directories(ton-analytics-wallets-events PUBLIC ../tondb-scanner/src)
  target_link_libraries(ton-analytics-wallets-events PUBLIC tondb-scanner validator)

  add_library(ton-analytics-wallets-stage STATIC WalletStage.cpp)
  target_compile_features(ton-analytics-wallets-stage PUBLIC cxx_std_20)
  target_link_libraries(ton-analytics-wallets-stage PUBLIC
    ton-analytics-wallets-events ton-analytics-wallets-metrics)

  add_library(ton-analytics-wallets-raw-inventory STATIC WalletRawInventory.cpp)
  target_compile_features(ton-analytics-wallets-raw-inventory PUBLIC cxx_std_20)
  target_link_libraries(ton-analytics-wallets-raw-inventory PUBLIC ton-analytics-wallets-stage)

  target_link_libraries(ton-analytics-wallets PRIVATE ton-analytics-wallets-raw-inventory)
  target_compile_definitions(ton-analytics-wallets PRIVATE TON_WALLETS_TON_ADAPTER_AVAILABLE=1)
endif()

add_executable(test-ton-analytics-wallets-cli cli_test.cpp)
add_executable(test-ton-analytics-wallets-pilot pilot_test.cpp)
target_compile_features(test-ton-analytics-wallets-cli PRIVATE cxx_std_20)
target_compile_features(test-ton-analytics-wallets-pilot PRIVATE cxx_std_20)

enable_testing()
add_test(NAME wallets-cli COMMAND test-ton-analytics-wallets-cli)
add_test(NAME wallets-pilot COMMAND test-ton-analytics-wallets-pilot)
add_test(NAME wallets-fail-closed COMMAND ton-analytics-wallets)
set_tests_properties(wallets-fail-closed PROPERTIES WILL_FAIL TRUE)

if(TON_WALLETS_TON_ADAPTER_AVAILABLE)
  add_executable(test-ton-analytics-wallets-extractor extractor_test.cpp)
  target_compile_features(test-ton-analytics-wallets-extractor PRIVATE cxx_std_20)
  target_link_libraries(test-ton-analytics-wallets-extractor PRIVATE ton-analytics-wallets-events)
  add_test(NAME wallets-extractor COMMAND test-ton-analytics-wallets-extractor)

  # Synthetic proof fixtures ONLY. The stage is not connected to NodeDB or
  # production day publication by registering this local native unit test.
  add_executable(test-ton-analytics-wallets-stage stage_test.cpp)
  target_compile_features(test-ton-analytics-wallets-stage PRIVATE cxx_std_20)
  target_link_libraries(test-ton-analytics-wallets-stage PRIVATE ton-analytics-wallets-stage)
  add_test(NAME wallets-stage COMMAND test-ton-analytics-wallets-stage)

  add_executable(test-ton-analytics-wallets-raw-inventory raw_inventory_test.cpp)
  target_compile_features(test-ton-analytics-wallets-raw-inventory PRIVATE cxx_std_20)
  target_link_libraries(test-ton-analytics-wallets-raw-inventory PRIVATE
    ton-analytics-wallets-raw-inventory)
  add_test(NAME wallets-raw-inventory COMMAND test-ton-analytics-wallets-raw-inventory)
endif()

add_executable(test-ton-analytics-wallets-metrics metrics_test.cpp)
target_compile_features(test-ton-analytics-wallets-metrics PRIVATE cxx_std_20)
target_link_libraries(test-ton-analytics-wallets-metrics PRIVATE ton-analytics-wallets-metrics)
add_test(NAME wallets-metrics COMMAND test-ton-analytics-wallets-metrics)
