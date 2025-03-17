#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_

#include "edge_defines.h"
#include <edge_call.h>
#include "keystone.h"

#define crypto_kx_PUBLICKEYBYTES 32

typedef struct encl_message_t {
  void* host_ptr;
  size_t len;
} encl_message_t;

int edge_init(Keystone::Enclave* enclave);

void print_buffer_wrapper(void* buffer);
unsigned long print_buffer(char* str);

void print_value_wrapper(void* buffer);
void print_value(unsigned long val);

void send_report_wrapper(void* buffer);
void send_report(void* shared_buffer, size_t len);

void wait_for_message_wrapper(void* buffer);
encl_message_t wait_for_message();

void send_reply_wrapper(void* buffer);
void send_reply(void* message, size_t len);

void wait_for_server_pubkey_wrapper(void* buffer);
void* wait_for_server_pubkey();

void get_current_feature_uid_wrapper(void *buffer);
int32_t *get_current_feature_uid();

void pass_license_data_wrapper(void* buffer);
void pass_license_data(ftr_license_t *feature_license_data);

#endif /* _EDGE_WRAPPER_H_ */