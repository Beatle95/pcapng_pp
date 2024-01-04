cmake_minimum_required (VERSION 3.16)
project (tests)

set(TEST_RESOURCES_PATH ${CMAKE_CURRENT_SOURCE_DIR}/resources/)
configure_file(path.h.in ${CMAKE_CURRENT_SOURCE_DIR}/path.h)

add_executable (reading_tests ${CMAKE_CURRENT_SOURCE_DIR}/reading_tests.cpp)
target_link_libraries (reading_tests PUBLIC gtest_main pcapng_pp)
add_test (NAME reading_tests COMMAND reading_tests)
