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
    include/pcapng_pp/pcapng_types.h
    include/pcapng_pp/pcapng_constants.h
    include/pcapng_pp/pcapng_file_reader.h
    include/pcapng_pp/pcapng_error.h
    include/pcapng_pp/pcapng_block.h
    include/pcapng_pp/pcapng_packet.h
    include/pcapng_pp/pcapng_interface.h

    src/pcapng_file_reader.cpp
    src/pcapng_error.cpp
    src/pcapng_block.cpp
    src/pcapng_packet.cpp
    src/pcapng_interface.cpp
)

# 'span' library contains tests which is not supported by ARM processors
# so we just add additional include directory for this library

target_include_directories(
    ${PROJECT_NAME} PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/3rdparty/span/include
)

if (${ENABLE_TESTS})
    enable_testing()
    set(gtest_force_shared_crt on)
    add_subdirectory(3rdparty/googletest)
    add_subdirectory(tests)
endif()
