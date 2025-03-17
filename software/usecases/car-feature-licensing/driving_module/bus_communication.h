#ifndef _KEYVISOR_BUS_COMMUNICATION_H_
#define _KEYVISOR_BUS_COMMUNICATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

int request_feature_nonce(int srv_sock, int32_t feature_uid, uint8_t *out_nonce, size_t *inout_nonce_size);

int send_feature_enable_request(int srv_sock, const uint8_t *token, size_t tokenlen, const uint8_t *iv, size_t ivlen, const uint8_t *tag, size_t taglen);

#ifdef __cplusplus
}
#endif

#endif /* _KEYVISOR_BUS_COMMUNICATION_H_ */