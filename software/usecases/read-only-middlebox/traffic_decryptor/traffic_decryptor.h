#ifndef _TRAFFIC_DECRYPTOR_H_
#define _TRAFFIC_DECRYPTOR_H_

#include <stdint.h>
#include "edge_defines.h" // session_handle_t

void perform_traffic_decryption(void);

#ifdef USE_OPENSSL_STUB_INSTEAD
int openssl_gcm_decrypt(session_handle_t *sess_handle, uint8_t *iv, uint8_t *tag, uint8_t *aad, size_t aad_len, uint8_t *cipher, size_t cipher_len);
#else
int keyvisor_gcm_decrypt(session_handle_t *sess_handle, uint8_t *iv, uint8_t *tag, uint8_t *aad, size_t aad_len, uint8_t *cipher, size_t cipher_len);
#endif

#endif /* _TRAFFIC_DECRYPTOR_H_ */