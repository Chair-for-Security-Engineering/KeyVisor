#ifndef _VENDOR_MAIN_H_
#define _VENDOR_MAIN_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../encl_message.h"

extern int fd_clientsock;
extern int fd_srv;

// previous main
int share_tls_keys(const char *hostname, bool ignore_valid_flag,
    const unsigned char *cli_tx_key, const unsigned char *cli_rx_key, size_t keylen,
    const unsigned char *cli_tx_iv, const unsigned char *cli_rx_iv, size_t ivlen,
    uint16_t src_port, uint16_t dst_port, uint32_t src_ip, uint32_t dst_ip);

void send_buffer(byte* buffer, size_t len);
byte* recv_buffer(size_t* len);

void send_buffer_to_decryptor(byte* buffer, size_t len);

#endif /* _VENDOR_MAIN_H_ */
