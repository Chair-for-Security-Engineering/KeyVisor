cmake_minimum_required(VERSION 3.10)
project(vendorService LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
  message("-- RELEASE build is chosen by default (specify CMAKE_BUILD_TYPE to choose a different one)")
endif()
message("-- Build type: ${CMAKE_BUILD_TYPE}")

# check if SDK has been built and KEYSTONE_SDK_DIR environment variable exists
if (NOT DEFINED ENV{KEYSTONE_SDK_DIR})
  message(FATAL_ERROR "Please set KEYSTONE_SDK_DIR environment variable to an installed SDK path")
endif()
set(KEYSTONE_SDK_DIR $ENV{KEYSTONE_SDK_DIR})

if (NOT DEFINED ENV{LIBSODIUM_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_DIR")
endif()
set(LIBSODIUM_DIR $ENV{LIBSODIUM_DIR})

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake" ${CMAKE_MODULE_PATH})

# find openssl (we only need the crypto lib)
find_package(OpenSSL REQUIRED)

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

message("C compiler: ${CMAKE_C_COMPILER}")
message("CXX compiler: ${CMAKE_CXX_COMPILER}")

# export include directory
include_directories(../include
  ${LIBSODIUM_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/verifier
  ../../../include
  ${OPENSSL_INCLUDE_DIR})

# set paths to the libraries
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)

# vendor service
add_executable(vendor_service
  vendor_main.cpp
  vendor_service.cpp
  ../tcp-connection.c
  ../include/enclave_expected_hash.h
  ../include/sm_expected_hash.h
)

target_link_libraries(vendor_service
  ${KEYSTONE_LIB_VERIFIER}
  ${LIBSODIUM_DIR}/.libs/libsodium.a
  OpenSSL::Crypto)
