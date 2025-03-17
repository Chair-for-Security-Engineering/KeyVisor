#ifndef _REMOTE_CLIENT_H_
#define _REMOTE_CLIENT_H_

#include <stdio.h>
#include "channel_msg.h"

#include <string>
#include <iostream>
#include <fstream>
#include "sodium.h"
#include "report.h"

#include "tls_session_data.h"

typedef unsigned char byte;

void remote_client_exit();
void remote_client_init();
byte* remote_client_pubkey(size_t* len);
void remote_client_get_report(void* buffer, int ignore_valid);
void remote_client_read_reply(unsigned char* data, size_t len);
void send_exit_message();
void send_session_data_message(session_data_t *buffer);
channel_message_t* generate_exit_message(size_t* finalsize);
channel_message_t* generate_session_data_message(uint8_t* buffer, size_t buffer_len, size_t* finalsize);

byte* remote_client_box(byte* msg, size_t size, size_t* finalsize);
void remote_client_unbox(unsigned char* buffer, size_t len);

#endif /* _REMOTE_CLIENT_H_ */
