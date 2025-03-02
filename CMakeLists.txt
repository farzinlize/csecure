cmake_minimum_required(VERSION 3.10)
project(libcs)

option(LIBCS_INSPECT "activate inspect mode" ON)
set(LIBCS_SIMPLE_SIZE 1024 CACHE STRING "size of a single message to test for encryption and decryption")

message(STATUS "configuring csecure library (libcs)")

add_library(libcs STATIC security.c)
target_include_directories(libcs PUBLIC includes)
target_compile_definitions(libcs PUBLIC 
    CMAKE_MAKE
    $<$<BOOL:${LIBCS_INSPECT}>:CS_INSPECT>
    LIBCS_SINGLE_SIZE=${LIBCS_SIMPLE_SIZE}
)

target_link_libraries(libcs PUBLIC gcrypt)

enable_testing()
add_subdirectory(unit-tests)