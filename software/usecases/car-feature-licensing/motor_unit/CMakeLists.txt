cmake_minimum_required(VERSION 3.10)
project(motorUnit LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug)
  message("-- RELEASE build is chosen by default (specify CMAKE_BUILD_TYPE to choose a different one)")
endif()
message("-- Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR};${CMAKE_CURRENT_SOURCE_DIR}/../../cmake" ${CMAKE_MODULE_PATH})

find_package(PROTOBUF-C REQUIRED)
find_package(MbedTLS REQUIRED)

# export include directory
include_directories(../../
  ../include/
  ${MBEDTLS_INCLUDE_DIRS}
  ${PROTOBUF_INCLUDE_DIR})

# motor unit
add_executable(motor_unit
  motor_unit.c
  ../../../shared/usock-connection.c
  ../car-bus-msg.pb-c.c
  ../../../external/handle_pb_prefix.c
  ../../car-bus-msg.pb-c.c
)

target_link_libraries(motor_unit
  ${MBEDCRYPTO_LIBRARY}
  ${PROTOBUF_LIBRARIES})
