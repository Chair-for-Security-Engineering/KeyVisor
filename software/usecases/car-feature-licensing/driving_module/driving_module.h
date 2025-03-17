#ifndef _KEYVISOR_DRIVING_MODULE_H_
#define _KEYVISOR_DRIVING_MODULE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "edge_defines.h"
#include "keyvisor/handle.h"

void run_driving_module(void);

#ifdef USE_OPENSSL_STUB_INSTEAD

int openssl_gcm_encrypt(const uint8_t *aes_128_key, const uint8_t *in_plaintext, uint8_t *in_iv, uint8_t *out_tag, uint8_t *in_aad, size_t aad_len, uint8_t *out_cipher, size_t in_data_len);

#else

int keyvisor_gcm_encrypt(const kv_handle_t *key_handle, uint8_t *inout_data, size_t in_data_len, uint8_t *out_iv, uint8_t *out_tag, uint8_t *in_aad, size_t aad_len);

#endif /* USE_OPENSSL_STUB_INSTEAD */

#ifdef __cplusplus
}
#endif

#endif /* _KEYVISOR_DRIVING_MODULE_H_ */