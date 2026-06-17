cmake_minimum_required(VERSION 3.10)
project(libsodium_crypto VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

set(SOURCES
    src/libsodium_crypto.c
)

add_library(libsodium_crypto SHARED ${SOURCES})

target_link_libraries(libsodium_crypto ${LIBSODIUM_LIBRARIES})

set_target_properties(libsodium_crypto PROPERTIES
    OUTPUT_NAME "libsodium_crypto"
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
)

install(TARGETS libsodium_crypto
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(FILES include/libsodium_crypto.h
    DESTINATION include
)

add_executable(example_usage examples/example_usage.c)
target_link_libraries(example_usage libsodium_crypto)

enable_testing()
add_executable(test_lib tests/test_lib.c)
target_link_libraries(test_lib libsodium_crypto)

add_test(NAME test_lib COMMAND test_lib)