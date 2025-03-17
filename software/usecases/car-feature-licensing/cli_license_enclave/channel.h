#ifndef _KEYVISOR_CHANNEL_H_
#define _KEYVISOR_CHANNEL_H_

#include <stddef.h>
#include <stdint.h>

void channel_init();
void channel_establish();
int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen);
size_t channel_get_send_size(size_t len);
int channel_send_license_query_message(int32_t feature_uid);
extern unsigned char server_pk[], server_sk[];
extern unsigned char client_pk[];
extern unsigned char rx[];
extern unsigned char tx[];

#endif /* _KEYVISOR_CHANNEL_H_ */
