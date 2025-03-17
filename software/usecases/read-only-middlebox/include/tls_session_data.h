#ifndef _KEYVISOR_TLS_SESSION_DATA_H_
#define _KEYVISOR_TLS_SESSION_DATA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h> // size_t
#include <string.h> // memcpy
#include <stdlib.h> // free

// TODO: this info might be transparent to user space TLS library
// TODO: probaby easier for kTLS, which should be able to know
/* assumes TCP/IPv4 for TLS */
typedef struct connection_info_t {
    uint16_t client_port, server_port;
    uint32_t client_ip, server_ip;
} connection_info_t;

typedef enum SESSION_KEY_TYPE {
    client_encrypt,     // tx
    client_mac,
    server_encrypt,     // rx
    server_mac,
} s_key_type_t;

// TODO: add seq. number?
typedef struct aes128_session_key_t {
    s_key_type_t key_type;
    uint8_t handshake_iv_tls12[4]; // warning: 12 Bytes in TLS 1.3
    uint64_t key[2]; // 128bit
    //size_t len;
    //char key[]; // Flexible member
} aes128_session_key_t;

/* send from client to enclave/server to share keys
 *
 * important: this is supposed to be sent over the wire, so all members are
 *      supposed to be located consecutively in one coherent buffer
 * 
 * WARNING: shallow copies don't copy sess_key[]
 * */
typedef struct session_data_t {
    connection_info_t conn_info;
    size_t num_keys;
    aes128_session_key_t sess_key[]; // `num_keys` many

#ifdef __cplusplus
    // prevent shallow copy
    session_data_t & operator=(const session_data_t &) = delete;
    session_data_t (const session_data_t &) = delete;
#endif

} session_data_t;

typedef struct session_data_crafter {
    size_t unused_key_slots;
    session_data_t *wip_sess_data;
} sess_data_crafter_t;

static inline size_t get_session_data_size(size_t num_keys) {
    return sizeof(session_data_t) + num_keys * sizeof(aes128_session_key_t);
}

/* cli_port_n, srv_port_n in network order (htons()); cli_ip, srv_ip as output by inet_addr() */
static inline sess_data_crafter_t *prepare_session_data(uint16_t cli_port_n, uint16_t srv_port_n,
    uint32_t cli_ip, uint32_t srv_ip, size_t num_keys) {

    sess_data_crafter_t *sess_crafter = (sess_data_crafter_t *)malloc(sizeof(sess_data_crafter_t));
    if (!sess_crafter) return NULL;

    session_data_t *sess_data = (session_data_t *)malloc(get_session_data_size(num_keys));
    if (!sess_data) {
        free(sess_crafter);
        return NULL;
    }

    sess_data->conn_info.client_port = cli_port_n;
    sess_data->conn_info.server_port = srv_port_n;
    sess_data->conn_info.client_ip = cli_ip;
    sess_data->conn_info.server_ip = srv_ip;

    sess_data->num_keys = num_keys;

    sess_crafter->unused_key_slots = sess_data->num_keys;
    sess_crafter->wip_sess_data = sess_data;

    return sess_crafter;
}

typedef enum SESSION_CRAFT_ERRORS {
    SC_NO_ERROR = 0x0,

    SC_NULL_BUFFERS = -0x1,
    SC_NO_FREE_KEY_SLOT = -0x2,
    SC_INVALID_SESS_PTR = -0x3,
    SC_INVALID_KEY_LEN = -0x4,
    SC_INVALID_IV_LEN = -0x5,

    SC_NOT_ALL_KEYS_ADDED = -0x10,
} s_craft_error_t;

static inline s_craft_error_t add_session_key(sess_data_crafter_t *sess_crafter, 
    s_key_type_t key_type, const uint8_t *iv, size_t iv_len,
    const uint8_t *key_buf, size_t key_len) {

    if (!sess_crafter || !key_buf) return SC_NULL_BUFFERS;
    if (!sess_crafter->unused_key_slots) return SC_NO_FREE_KEY_SLOT;
    if (!sess_crafter->wip_sess_data) return SC_INVALID_SESS_PTR;
    // currently we only expect 128 bit (16 Byte) AES keys
    if (key_len != 16) return SC_INVALID_KEY_LEN;
    // we currently on support TLS 1.2 with AEAD
    if (iv_len != 4) return SC_INVALID_IV_LEN;

    size_t key_slot = sess_crafter->wip_sess_data->num_keys - sess_crafter->unused_key_slots;
    aes128_session_key_t *key = &sess_crafter->wip_sess_data->sess_key[key_slot];
    if (iv_len != sizeof(key->handshake_iv_tls12)) return SC_INVALID_IV_LEN;

    key->key_type = key_type;
    memcpy(key->handshake_iv_tls12, iv, iv_len);
    //key->len = key_len;
    memcpy(key->key, key_buf, 16);
    sess_crafter->unused_key_slots--;

    return SC_NO_ERROR;
}

static inline s_craft_error_t finalize_session_data(sess_data_crafter_t *sess_crafter, session_data_t **out_sess_data) {
    if (!sess_crafter || !out_sess_data) return SC_NULL_BUFFERS;
    if (!sess_crafter->wip_sess_data) return SC_INVALID_SESS_PTR;
    if (sess_crafter->unused_key_slots > 0) return SC_NOT_ALL_KEYS_ADDED;

    *out_sess_data = sess_crafter->wip_sess_data;
    sess_crafter->wip_sess_data = NULL;
    free(sess_crafter);

    return SC_NO_ERROR;
}

/* free crafter and encapsulated session data */
static inline void free_unfinished_session_crafter(sess_data_crafter_t *sess_crafter) {
    if (!sess_crafter) return;
    if (sess_crafter->wip_sess_data) free(sess_crafter->wip_sess_data);
    free(sess_crafter);
}

#ifdef __cplusplus
}
#endif

#endif /* _KEYVISOR_TLS_SESSION_DATA_H_ */