cmake_minimum_required(VERSION 3.10)
project(roMiddlebox LANGUAGES C CXX ASM)

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

if (NOT DEFINED ENV{LIBSODIUM_DIR})
  message(FATAL_ERROR "Please set LIBSODIUM_DIR")
endif()
set(LIBSODIUM_DIR $ENV{LIBSODIUM_DIR})

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

include($ENV{KEYSTONE_SDK_DIR}/cmake/macros.cmake)

message("C compiler: ${CMAKE_C_COMPILER}")
message("CXX compiler: ${CMAKE_CXX_COMPILER}")

# find openssl (we only need the crypto lib)
find_package(OpenSSL REQUIRED)

# find pcap
find_package(PCAP REQUIRED)

# export include directory
include_directories(include
  ${LIBSODIUM_DIR}/include
  ${KEYSTONE_SDK_DIR}/include
  ${KEYSTONE_SDK_DIR}/include/host
  ${KEYSTONE_SDK_DIR}/include/edge
  ${KEYSTONE_SDK_DIR}/include/verifier
  ../../include
  traffic_decryptor
  ${OPENSSL_INCLUDE_DIR}
  ${PCAP_INCLUDE_DIRS})

# set paths to the libraries
set(KEYSTONE_LIB_HOST ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a)
set(KEYSTONE_LIB_EDGE ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)
set(KEYSTONE_LIB_VERIFIER ${KEYSTONE_SDK_DIR}/lib/libkeystone-verifier.a)
set(KEYSTONE_LIB_EAPP ${KEYSTONE_SDK_DIR}/lib/libkeystone-eapp.a)

# find phtreads
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# find program "makeself"
find_program(MAKESELF makeself)

# enclave
add_subdirectory(keysrv_enclave)
set(host_bin middlebox-host.riscv)
set(host_src middlebox_main.cpp keysrv_host.cpp edge_wrapper.cpp traffic_decryptor/traffic_decryptor.cpp traffic_decryptor/sess_info_db.cpp traffic_decryptor/traffic_monitor.cpp ../tcp-connection.c)
set(eyrie_plugins "freemem")
set(package_name "ro_middlebox.ke")
set(package_script "./middlebox-host.riscv")

add_executable(${host_bin} ${host_src})
target_link_libraries(${host_bin} ${KEYSTONE_LIB_HOST} ${KEYSTONE_LIB_EDGE} ${KEYSTONE_LIB_VERIFIER} Threads::Threads OpenSSL::Crypto ${PCAP_LIBRARIES})

set(eyrie_files_to_copy eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  "v1.0.0"
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

add_keystone_package(packagedemo
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} keysrv_enclave/keysrv_enclave.eapp_riscv ${host_bin})

add_dependencies(packagedemo ${eapp_bin}-eyrie)
