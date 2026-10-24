# Local target ONLY; chief owns root registration and pilot slot. Secondary
# NodeDB opens remain disabled unless explicitly built with the switch below.
option(TON_VALIDATORS_SECONDARY_SAFETY_REVIEWED
  "Enable Validators secondary NodeDB open ONLY after independent review" OFF)

add_executable(ton-analytics-validators main.cpp ValidatorFacts.cpp ValidatorCoreBridge.cpp
  ../tondb-scanner/src/analytics/validators/ValidatorStage.cpp
  ../tondb-scanner/src/analytics/validators/ValidatorSnapshot.cpp
  ../tondb-scanner/src/analytics/validators/ValidatorElectionObservation.cpp)
target_compile_features(ton-analytics-validators PRIVATE cxx_std_20)
target_include_directories(ton-analytics-validators PRIVATE ../tondb-scanner/src)
target_link_libraries(ton-analytics-validators PRIVATE tondb-scanner validator)
if(NOT TARGET ton-analytics-core)
  message(FATAL_ERROR "Validators requires chief-registered ton-analytics-core before this target")
endif()
target_link_libraries(ton-analytics-validators PRIVATE ton-analytics-core)
if(TON_VALIDATORS_SECONDARY_SAFETY_REVIEWED)
  target_compile_definitions(ton-analytics-validators PRIVATE TON_VALIDATORS_SECONDARY_SAFETY_REVIEWED=1)
endif()

add_executable(test-ton-analytics-validators-options options_test.cpp)
target_compile_features(test-ton-analytics-validators-options PRIVATE cxx_std_17)
enable_testing()
add_test(NAME ton-analytics-validators-options COMMAND test-ton-analytics-validators-options)
