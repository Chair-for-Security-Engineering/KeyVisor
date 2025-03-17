add_executable(keysrv_enclave.eapp_riscv
  keysrv_enclave.c
  edge_wrapper.c
  channel.c
  khandles.c)

include_directories(include
  ${KEYSTONE_SDK_DIR}/include/app
  ../../../include)

target_link_libraries(keysrv_enclave.eapp_riscv
  ${KEYSTONE_LIB_EDGE}
  ${KEYSTONE_LIB_EAPP}
  ${LIBSODIUM_DIR}/.libs/libsodium.a)

set_target_properties(keysrv_enclave.eapp_riscv
  PROPERTIES LINK_FLAGS "-nostdlib -static -T ${CMAKE_CURRENT_SOURCE_DIR}/app.lds")
