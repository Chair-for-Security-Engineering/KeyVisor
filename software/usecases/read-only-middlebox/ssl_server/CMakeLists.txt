cmake_minimum_required(VERSION 3.10)
project(sslServer LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
  message("-- DEBUG build is chosen by default (specify CMAKE_BUILD_TYPE to choose a different one)")
endif()
message("-- Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})

# find mbedtls
find_package(MbedTLS REQUIRED)

# export include directory
include_directories(${MBEDTLS_INCLUDE_DIRS})

# remote client
add_executable(ssl_server
  ssl_server.c
)

target_link_libraries(ssl_server
  ${MBEDTLS_LIBRARY}
  ${MBEDX509_LIBRARY}
  ${MBEDCRYPTO_LIBRARY})
