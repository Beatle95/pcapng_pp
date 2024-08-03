cmake_minimum_required(VERSION 3.12)
project(
    pcapng_pp 
    DESCRIPTION "Simple library for reading/writing pcapng files"
    VERSION 0.0.1 
    LANGUAGES CXX
    HOMEPAGE_URL "https://github.com/Beatle95/pcapng_pp"
)

option(ENABLE_TESTS "Enable tests" OFF)

add_library(
    ${PROJECT_NAME} STATIC
    src/pcapng_file_reader.cpp
    src/pcapng_file_writer.cpp
    src/pcapng_error.cpp
    src/pcapng_block.cpp
    src/pcapng_packet.cpp
    src/pcapng_interface.cpp
    src/pcapng_packet_block.cpp
    src/pcapng_functions.cpp
)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

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
