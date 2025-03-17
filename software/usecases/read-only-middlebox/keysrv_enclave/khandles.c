#include "khandles.h"
#include "tls_session_data.h"
#include "edge_wrapper.h"
#include "edge_defines.h"

#include <keyvisor/key-handle-helpers.h>

static inline void print_byte_array_enc(uint8_t *buf, size_t buf_len) {
    for (size_t i=0; i<buf_len; i++)
        ocall_print_value(buf[i]);
    ocall_print_buffer("\n");
}

void handle_session_keys(char* sess_data_buf, size_t len) {
  // sanity checks for buffer size
  if (len < sizeof(session_data_t) || !sess_data_buf) {
    ocall_print_buffer("session data NULL or too short\n");
    return;
  }
  session_data_t *sess_data = (session_data_t *) sess_data_buf;
  if (len != get_session_data_size(sess_data->num_keys)) {
    ocall_print_buffer("session data not expected length for given number of keys; expected: ");
    ocall_print_value(get_session_data_size(sess_data->num_keys));
    ocall_print_buffer("got: ");
    ocall_print_value(len);
    return;
  }

  ocall_print_buffer("Going to wrap keys into handles\n");

  sess_kbundle_t *sess_key_bundle = (sess_kbundle_t *)malloc(get_sess_bundle_size(sess_data->num_keys));
  if (!sess_key_bundle) {
    ocall_print_buffer("failed allocation key bundle: OOM\n");
    return;
  }
  sess_key_bundle->num_handles = sess_data->num_keys;
  memcpy(&sess_key_bundle->conn_info, &sess_data->conn_info, sizeof(connection_info_t));

  size_t i;
  for (i=0; i<sess_data->num_keys; i++) {
    ocall_print_buffer("key to wrap:\n");
    print_byte_array_enc((uint8_t *)sess_data->sess_key[i].key, 16);

    // unbound, decrypt-only key handle
    kv_handle_t *hndl = kv_create_key_handle_ext(
      sess_data->sess_key[i].key, KV_PERMIT_DECRYPT, 0, 0);
    if (!hndl) {
      ocall_print_buffer("Failed creating handle for key slot:");
      ocall_print_value(i);
      free(sess_key_bundle);
      return;
    }

    // fill in data for next session handle data in bundle
    session_handle_t *new_bundle_shndl = &sess_key_bundle->sess_handles[i];

    new_bundle_shndl->key_type = sess_data->sess_key[i].key_type;

    memcpy(&new_bundle_shndl->handshake_iv_tls12, sess_data->sess_key[i].handshake_iv_tls12, sizeof(sess_data->sess_key[i].handshake_iv_tls12));

    // TODO: what start value?! handshake is already (partially?) done?
    //    -- but seq. numbers reset afterwards
    new_bundle_shndl->net_tls_seq_num = 0;
    
    memcpy(&new_bundle_shndl->handle, hndl, sizeof(kv_handle_t));
#ifdef USE_OPENSSL_STUB_INSTEAD
    memcpy(new_bundle_shndl->aes_128_key, (uint8_t *)sess_data->sess_key[i].key, 16);
#endif

    free(hndl); // copied, so free in-enclave copy
    // wipe AES key
    memset((uint8_t *)sess_data->sess_key[i].key, 0, 16);
  }

  ocall_pass_key_handle(sess_key_bundle);

  free(sess_key_bundle);
}