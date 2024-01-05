cmake_minimum_required(VERSION 3.12)
project(
    pcapng_pp 
    DESCRIPTION "Simple library for reading/writing pcapng files"
    VERSION 0.0.1 
    LANGUAGES CXX
    HOMEPAGE_URL "https://github.com/Beatle95/pcapng_pp"
)

option(ENABLE_TESTS "Enable tests" OFF)

set(CMAKE_CXX_STANDARD          17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS       OFF)

add_library(
    ${PROJECT_NAME} STATIC
    src/pcapng_file_reader.h
    src/pcapng_file_reader.cpp
    src/pcapng_error.h
    src/pcapng_error.cpp
    src/pcapng_block.h
    src/pcapng_block.cpp
    src/packet.h
    src/packet.cpp
    src/pcapng_types.h
    src/pcapng_constants.h
)

# 'span' library contains tests which is not supported by ARM processors
# so we just add additional include directory for this library

target_include_directories(
    ${PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/3rdparty/span/include
)

if (${ENABLE_TESTS})
    enable_testing()
    set(gtest_force_shared_crt on)
    add_subdirectory(3rdparty/googletest)
    add_subdirectory(tests)
endif()
