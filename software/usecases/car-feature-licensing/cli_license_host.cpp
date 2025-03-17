#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h" // TODO: mostly unused

#include "edge_defines.h" // USE_OPENSSL_STUB_INSTEAD

#include <keyvisor/handle.h>
#include <keyvisor/debug_handle.h>

#include "include/tcp-connection.h"

#include <arpa/inet.h>

#include "cli_license_host.h"
#include "print-utils.h"

#define PRINT_MESSAGE_BUFFERS 1

/* We hardcode these for demo purposes. */
const char* enc_path = "cli_license_enclave.eapp_riscv";
const char* runtime_path = "eyrie-rt";

int fd_srvsock;  // socket to server (when connected)
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

/* Send (len||buffer) via socket to client */
void send_buffer(byte* buffer, size_t len){
  write(fd_srvsock, &len, sizeof(size_t));
  write(fd_srvsock, buffer, len);
}

/* Receive (msg-len||msg) via socket from client */
byte* recv_buffer(size_t* len) {
  read(fd_srvsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);

  read(fd_srvsock, reply, reply_size);
  *len = reply_size;
  return reply;
}

// debug printing
void print_hex_data(unsigned char* data, size_t len) {
  unsigned int i;
  std::string str;

  for(i=0; i<len; i+=1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();

    if(i>0 && (i+1)%8 == 0) {
      if((i+1)%32 == 0) {
	      str += "\n";
      } else {
	      str += " ";
      }
    }
  }

  printf("%s\n\n",str.c_str());
}


/* ---- START of OCALLs (edge calls) ---- */

// OCALL_PRINT_BUFFER (print_buffer_wrapper)
unsigned long print_buffer(char* str) {
  printf("[SE] %s",str);
  return strlen(str);
}

// OCALL_PRINT_VALUE (print_value_wrapper)
void print_value(unsigned long val) {
  printf("[SE] value: %#x\n",val);
  return;
}

// OCALL_SEND_REPLY (send_reply_wrapper)
void send_reply(void* data, size_t len) {
  printf("[EH] Sending encrypted reply:\n");

  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)data, len);

  send_buffer((byte*)data, len);
}

// OCALL_WAIT_FOR_SERVER_PUBKEY (wait_for_server_pubkey_wrapper)
void* wait_for_server_pubkey() {
  size_t len;
  return recv_buffer(&len);
}

// OCALL_WAIT_FOR_MESSAGE (wait_for_message_wrapper)
encl_message_t wait_for_message() {
  size_t len;

  void* buffer = recv_buffer(&len);

  printf("[EH] Got an encrypted message:\n");
  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

// OCALL_SEND_REPORT (send_report_wrapper)
void send_report(void* buffer, size_t len) {
  send_buffer((byte*)buffer, len);
}

static int32_t current_feature_uid;

// OCALL_GET_CURRENT_FEATURE_UID (get_current_feature_uid_wrapper)
int32_t *get_current_feature_uid() {
  /* like wait_for_message of keystone-demo --- although I don't see how
   * that heap memory is ever free'd (maybe internally by keystone as part
   * of the shared memory handling) */
  int32_t *curr_ftr_ptr = (int32_t *)malloc(sizeof(current_feature_uid));
  assert(curr_ftr_ptr);
  *curr_ftr_ptr = current_feature_uid;
  return curr_ftr_ptr;
}

// helper function
void set_current_feature_uid(int32_t feature_uid) {
  current_feature_uid = feature_uid;
}

static ftr_license_t pending_feature_license_data;

// OCALL_PASS_LICENSE_DATA (pass_license_data_wrapper)
void pass_license_data(ftr_license_t *feature_license_data) {
  assert(feature_license_data);

  printf("usage counter: %d\n", feature_license_data->usage_counter);

#ifdef USE_OPENSSL_STUB_INSTEAD
  print_byte_array(feature_license_data->aes_128_key, 16);
#else
  print_handle(&feature_license_data->ftr_khandle);
#endif

  // prepare passing to driving_module
  memcpy(&pending_feature_license_data, feature_license_data, sizeof(ftr_license_t));
}

/* ---- END of OCALLs (edge calls) ---- */



int license_client_request_license(int32_t feature_uid, void *out_khandle, size_t *inout_outlen, int32_t *out_counter) {
  assert(out_khandle && inout_outlen && out_counter);
#ifdef USE_OPENSSL_STUB_INSTEAD
  assert(*inout_outlen >= 16);
#else
  assert(*inout_outlen >= sizeof(kv_handle_t));
#endif

  printf("HOST: Gonna wait connect to remote vendor service via TCP before starting the enclave.\n");

  /* Connect to remote vendor service (TCP/IP) */
  fd_srvsock = kv_create_tcp_client_socket();
  if (fd_srvsock < 0) {
    printf("Failed connecting to vendor service\n");
    return -1;
  }

  printf("[EH] Got connected to remote vendor service\n");

  Keystone::Enclave enclave;
  Keystone::Params params;

  /* Setup and call into enclave */
  if(enclave.init(enc_path, runtime_path, params) != Keystone::Error::Success){
    printf("HOST: Unable to start enclave\n");
    close(fd_srvsock);
    return -1;
  }

  edge_init(&enclave);

  long unsigned int enclave_return_value = 1337;

  Keystone::Error rval = enclave.run(&enclave_return_value);
  printf("rval: %i\n",rval);

  if (rval != Keystone::Error::Success) {
    printf("Failed running enclave\n");
    return -1;
  }

  if (enclave_return_value != 0) {
    printf("Failed requesting feature license.\n");
    return -1;
  }

  // usage counter and key-handle
  *out_counter = pending_feature_license_data.usage_counter;
#ifdef USE_OPENSSL_STUB_INSTEAD
  memcpy(out_khandle, pending_feature_license_data.aes_128_key, 16);
  *inout_outlen = 16;
#else
  memcpy(out_khandle, &pending_feature_license_data.ftr_khandle, sizeof(kv_handle_t));
  *inout_outlen = sizeof(kv_handle_t);
#endif

  return 0;
}