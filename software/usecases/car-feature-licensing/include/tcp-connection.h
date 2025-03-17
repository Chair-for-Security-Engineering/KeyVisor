#ifndef __KEYVISOR_TCP_CONNECTION_H__
#define __KEYVISOR_TCP_CONNECTION_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

extern const char *KV_SRV_SOCK_IP;
extern const uint16_t KV_SRV_SOCK_PORT;

int kv_create_tcp_server_socket(void);
int kv_create_tcp_client_socket(void);

#ifdef __cplusplus
}
#endif

#endif /* __KEYVISOR_TCP_CONNECTION_H__ */