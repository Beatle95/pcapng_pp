cmake_minimum_required (VERSION 3.16)
project (tests)

# copy resources to bin directory, so tests could access them
file(COPY resources/ DESTINATION ${EXECUTABLE_OUTPUT_PATH}/test_resources)

add_executable (opening_tests ${CMAKE_CURRENT_SOURCE_DIR}/opening_tests.cpp)
target_link_libraries (opening_tests PUBLIC gtest_main pcapng_pp)
add_test (NAME opening_tests COMMAND opening_tests)
