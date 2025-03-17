#ifndef __KEYVISOR_PRODCONSUM_USOCK_CONNECTION_H__
#define __KEYVISOR_PRODCONSUM_USOCK_CONNECTION_H__

#ifdef __cplusplus
extern "C" {
#endif

extern const char *KV_SRV_SOCK_PATH;

int kv_create_server_socket(void);
int kv_create_client_socket(void);

#ifdef __cplusplus
}
#endif

#endif /* __KEYVISOR_PRODCONSUM_USOCK_CONNECTION_H__ */
