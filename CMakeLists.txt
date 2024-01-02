cmake_minimum_required(VERSION 3.12)
project(
    pcapng_pp 
    DESCRIPTION "Simple library for reading/writing pcapng files"
    VERSION 0.0.1 
    LANGUAGES CXX
    HOMEPAGE_URL "https://github.com/Beatle95/pcapng_pp"
)

option(ENABLE_TESTS "Enable tests" OFF)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin) 
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS       OFF)

add_library(
    ${PROJECT_NAME} STATIC
    src/pcapng_file_reader.h
    src/pcapng_file_reader.cpp
    src/pcapng_error.h
    src/pcapng_error.cpp
    src/pcapng_block_body.h
    src/types.h
)

target_include_directories(
    ${PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/src
)

if (${ENABLE_TESTS})
    enable_testing()
    set(gtest_force_shared_crt on)
    add_subdirectory(3rdparty/googletest)
    add_subdirectory(tests)
endif()
