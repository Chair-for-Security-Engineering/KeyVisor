#ifndef _EDGE_DEFINES_H_
#define _EDGE_DEFINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <keyvisor/handle.h>
#include "tls_session_data.h"

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_SEND_REPORT 3
#define OCALL_WAIT_FOR_MESSAGE 4
#define OCALL_SEND_REPLY 5
#define OCALL_WAIT_FOR_CLIENT_PUBKEY 6

#define OCALL_PASS_SESSION_KEY_BUNDLE 7
#define OCALL_WAIT_FOR_TCP_CLIENT 8

//#define USE_OPENSSL_STUB_INSTEAD 1
#undef USE_OPENSSL_STUB_INSTEAD

typedef struct session_handle_t {
    s_key_type_t key_type;
    uint8_t handshake_iv_tls12[4]; // warning: 12 Bytes in TLS 1.3
    uint64_t net_tls_seq_num; // starts at 0, must be +1 per record in that direction
    kv_handle_t handle;
#ifdef USE_OPENSSL_STUB_INSTEAD
    uint8_t aes_128_key[16];
#endif
} session_handle_t;

/* argument for OCALL_PASS_SESSION_KEY_BUNDLE
 *
 * WARNING: shallow copy will not copy sess_handles[]
 */
// TODO: simplify -- 1 client, 1 server key; add seq. number to each
typedef struct sess_key_bundle {
    connection_info_t conn_info;
    size_t num_handles;
    session_handle_t sess_handles[];

#ifdef __cplusplus
    // prevent shallow copy
    sess_key_bundle & operator=(const sess_key_bundle &) = delete;
    sess_key_bundle (const sess_key_bundle &) = delete;
#endif

} sess_kbundle_t;

static inline size_t get_sess_bundle_size(size_t num_handles) {
    return sizeof(sess_kbundle_t) + num_handles * sizeof(session_handle_t);
}

#ifdef __cplusplus
}
#endif

#endif /* _EDGE_DEFINES_H_ */
