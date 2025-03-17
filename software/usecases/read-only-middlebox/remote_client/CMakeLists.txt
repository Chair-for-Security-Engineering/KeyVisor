cmake_minimum_required(VERSION 3.10)
project(remoteClient LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
  message("-- DEBUG build is chosen by default (specify CMAKE_BUILD_TYPE to choose a different one)")
endif()
message("-- Build type: ${CMAKE_BUILD_TYPE}")

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBSODIUM_CLIENT_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_CLIENT_DIR")
endif()
set(LIBSODIUM_CLIENT_DIR $ENV{LIBSODIUM_CLIENT_DIR})

# find mbedtls
find_package(MbedTLS REQUIRED)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

message("C compiler: ${CMAKE_C_COMPILER}")
message("CXX compiler: ${CMAKE_CXX_COMPILER}")

# export include directory
include_directories(../include
  ${LIBSODIUM_CLIENT_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/verifier
  ../../../include
  ${MBEDTLS_INCLUDE_DIRS})

# set paths to the libraries
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)

# remote client
add_executable(remote_client
  ssl_client1.cpp
  client_main.cpp
  remote_client.cpp
  ../tcp-connection.c
  ../include/enclave_expected_hash.h
  ../include/sm_expected_hash.h
)

target_link_libraries(remote_client
  ${KEYSTONE_LIB_VERIFIER}
  ${LIBSODIUM_CLIENT_DIR}/.libs/libsodium.a
  ${MBEDTLS_LIBRARY}
  ${MBEDX509_LIBRARY}
  ${MBEDCRYPTO_LIBRARY})
