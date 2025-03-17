#include "khandles.h"
#include "channel_msg.h"
#include "edge_wrapper.h"
#include "edge_defines.h"

#include <keyvisor/key-handle-helpers.h>

static inline void print_byte_array_enc(uint8_t *buf, size_t buf_len) {
    for (size_t i=0; i<buf_len; i++)
        ocall_print_value(buf[i]);
    ocall_print_buffer("\n");
}

// wrap into counter-restricted handle
// pass (key/handle, counter) out of enclave via OCALL
int handle_feature_license(uint8_t *license_buffer, size_t len) {
  // sanity checks for buffer size
  if (len != sizeof(license_t) || !license_buffer) {
    ocall_print_buffer("license data NULL or unexpected length\n");
    return -1;
  }
  license_t *ftr_license = (license_t *) license_buffer;

  ocall_print_buffer("Going to wrap key into counter-limited handle\n");

  ftr_license_t *ocall_license_data = (ftr_license_t *)malloc(sizeof(ftr_license_t));
  if (!ocall_license_data) {
    ocall_print_buffer("failed allocation of OCALL license data struct: OOM\n");
    return -1;
  }

  ocall_license_data->usage_counter = ftr_license->usage_counter;

#ifdef USE_OPENSSL_STUB_INSTEAD
  memcpy(ocall_license_data->aes_128_key, ftr_license->aes_128_key, 16);
#else
  ocall_print_buffer("key to wrap:\n");
  print_byte_array_enc(ftr_license->aes_128_key, 16);

  // unbound, counter-restricted, encrypt-only key handle
  kv_handle_t *hndl = kv_create_key_handle_ext(
    ftr_license->aes_128_key, KV_PERMIT_ENCRYPT, ftr_license->usage_counter, KV_ENABLE_USAGE_COUNTER);
  if (!hndl) {
    ocall_print_buffer("Failed creating key handle");
    free(ocall_license_data);
    return -1;
  }
    
  memcpy(&ocall_license_data->ftr_khandle, hndl, sizeof(kv_handle_t));
  free(hndl); // copied, so free in-enclave copy
#endif

  // wipe AES key
  memset(ftr_license->aes_128_key, 0, 16);

  ocall_pass_license_data(ocall_license_data);

  free(ocall_license_data);

  return 0;
}