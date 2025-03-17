#ifndef _VENDOR_SERVICE_H_
#define _VENDOR_SERVICE_H_

#include <stdio.h>
#include "channel_msg.h"

#include <string>
#include <iostream>
#include <fstream>
#include "sodium.h"
#include "report.h"

typedef unsigned char byte;

void vendor_service_exit();
void vendor_service_init();
int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen);
byte* vendor_service_pubkey(size_t* len);
void vendor_service_get_report(void* buffer, int ignore_valid);
void vendor_service_read_reply(unsigned char* data, size_t len);
void send_exit_message();
void send_license_data_message(license_t *buffer);
channel_message_t* generate_exit_message(size_t* finalsize);
channel_message_t* generate_license_data_message(uint8_t* buffer, size_t buffer_len, size_t* finalsize);

byte* vendor_service_box(byte* msg, size_t size, size_t* finalsize);
void vendor_service_unbox(unsigned char* buffer, size_t len);

#endif /* _VENDOR_SERVICE_H_ */
