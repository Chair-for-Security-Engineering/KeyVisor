#ifndef _EDGE_WRAPPER_H_
#define _EDGE_WRAPPER_H_
#include "edge_call.h"
#include "edge_defines.h"

void edge_init();

unsigned long ocall_print_buffer(char* data);
void ocall_print_value(unsigned long val);
void ocall_wait_for_message(struct edge_data *msg);
void ocall_wait_for_server_pubkey(unsigned char* pk, size_t len);
void ocall_send_report(char* buffer, size_t len);
void ocall_send_reply(unsigned char* data, size_t len);
void ocall_get_current_feature_uid(struct edge_data *msg);
void ocall_pass_license_data(ftr_license_t *feature_license_data);

#endif /* _EDGE_WRAPPER_H_ */