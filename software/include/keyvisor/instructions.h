#ifndef __KEYVISOR_INSTRUCTIONS_H__
#define __KEYVISOR_INSTRUCTIONS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "./handle.h"
#include "./rocc.h"

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>


/* Required to extract IV from io struct at the moment.
 * bytes must be >= 12 Bytes to fit the GCM IV */
static inline void kv_iv_to_bytes(kv_io_t *aes_io, uint8_t* out_gcm_iv, size_t out_len) {
    assert(out_len >= 12);

    uint64_t high = aes_io->iv_high, low = aes_io->iv_low;
    // note: highest 4 B of iv_high are junk, so skip them
    for(int i=3; i>=0; i--){
        out_gcm_iv[i] = high & 0xff;
        high >>= 8;
    }
    for(int i=11; i>=4; i--){
        out_gcm_iv[i] = low & 0xff;
        low >>= 8;
    }
}

/* Required to fill IV in io struct at the moment.
 * returns 0 on success; |bytes| must be 12 Bytes (GCM IV) */
static inline void kv_bytes_to_iv(kv_io_t *aes_io, const uint8_t* gcm_iv, size_t iv_len) {
    assert(iv_len == 12);

    aes_io->iv_high = 0;
    aes_io->iv_low = 0;
    // first 4 Bytes are junk, because |low|+|high| = 128b, but IV uses 96b
    for(int i=0; i<4; i++) {
        aes_io->iv_high |= gcm_iv[i];
        if(i!=3) aes_io->iv_high <<= 8;
    }
    for(int i=4; i<12; i++) {
        aes_io->iv_low |= gcm_iv[i];
        if(i!=11) aes_io->iv_low <<= 8;
    }
}


// TODO: 0 (success) and 1 (fail) are same for all, but >1 not (yet)
enum kv_status {
    KV_SUCCESS = 0,
    KV_IO_FAIL = 1,
    KV_NO_ENTROPY,
    KV_SRAM_FULL,
    KV_INVALID_ATTRIBUTES,
    KV_NO_CPU_KEY,

    KV_SUCCESS_KEY_REPLACED, // artifical one for load cpukey
};

typedef enum kv_status kv_status_t;

#ifdef KV_MOCK
#undef ROCC_INSTRUCTION_DSS
#define ROCC_INSTRUCTION_DSS(a,b,c,d,e)

int MOCK_WRAPKEY(kv_wrap_t *in_handle_attributes, kv_handle_t *out_handle) {
    out_handle->privileges = in_handle_attributes->privileges;
    out_handle->crypto_algo = in_handle_attributes->aes_mode;
    out_handle->crypto_attr = in_handle_attributes->crypto_attributes;
    out_handle->exattr_map = in_handle_attributes->exattr_map;
    // out_handle->pID = in_handle_attributes->pID;
    out_handle->attr_flags = in_handle_attributes->ext_attr_flags;
    
    out_handle->reserved = 0;
    //out_handle->globHandleIndex = 0;
    out_handle->timestamp = 0;
    // out_handle->reserved2 = 0;
    // out_handle->reserved3 = 0;

    //todo
    out_handle->AES_GCM_TAG[0] = 0xAFFEAFFEAFFEAFFE;
    out_handle->AES_GCM_TAG[1] = 0xAFFEAFFEAFFEAFFE;
    out_handle->AES_GCM_CT[0] = 0xAFFEAFFEAFFEAFFE;
    out_handle->AES_GCM_CT[1] = 0xAFFEAFFEAFFEAFFE;

    return KV_SUCCESS;
}

int MOCK_ENCRYPT(struct io_struct *aes_io, struct handle *handle) {
    handle->AES_GCM_TAG[0] = 0xAFFEAFFEAFFEAFFE;
    handle->AES_GCM_TAG[1] = 0xAFFEAFFEAFFEAFFE;
    return KV_SUCCESS;
}

int MOCK_DECRYPT(struct io_struct *aes_io, struct handle *handle) {
    handle->AES_GCM_TAG[0] = 0xAFFEAFFEAFFEAFFE;
    handle->AES_GCM_TAG[1] = 0xAFFEAFFEAFFEAFFE;
    return KV_SUCCESS;
}

int MOCK_LOADCPUKEY(uint64_t key_low, uint64_t key_high) {
    // NOP, just succeed
    return KV_SUCCESS;
}

int MOCK_REVOKE(struct handle *handle) {
    // NOP, just succeed
    return KV_SUCCESS;
}

#else

//void WRAPKEY(int ret_val, struct wrap_data *handle_attrs, struct handle *handle); 
//#define WRAPKEY(rd, rs1, rs2) ROCC_INSTRUCTION_DSS(2, rd, rs1, rs2, 1);
int __WRAPKEY(struct wrap_data *handle_attrs, struct handle *handle) {
    int tmp_ret_val;
    ROCC_INSTRUCTION_DSS(2, tmp_ret_val, handle_attrs, handle, 1);
    return tmp_ret_val;
}

//void ENCRYPT(int ret_val, struct io_struct *aes_io, struct handle *handle);
//#define ENCRYPT(rd, rs1, rs2) ROCC_INSTRUCTION_DSS(2, rd, rs1, rs2, 2);
int __ENCRYPT(struct io_struct *aes_io, const struct handle *handle) {
    int tmp_ret_val;
    ROCC_INSTRUCTION_DSS(2, tmp_ret_val, aes_io, handle, 2);
    return tmp_ret_val;
}

//void DECRYPT(int ret_val, struct io_struct *aes_io, struct handle *handle);
//#define DECRYPT(rd, rs1, rs2) ROCC_INSTRUCTION_DSS(2, rd, rs1, rs2, 3);
int __DECRYPT(struct io_struct *aes_io, const struct handle *handle) {
    int tmp_ret_val;
    ROCC_INSTRUCTION_DSS(2, tmp_ret_val, aes_io, handle, 3);
    return tmp_ret_val;
}

//void LOADCPUKEY(int ret_val, uint64_t key_low, uint64_t key_high);
//#define LOADCPUKEY(rd, rs1, rs2) ROCC_INSTRUCTION_DSS(2, rd, rs1, rs2, 0);
int __LOADCPUKEY(uint64_t key_low, uint64_t key_high) {
    int tmp_ret_val;
    ROCC_INSTRUCTION_DSS(2, tmp_ret_val, key_low, key_high, 0);
    return tmp_ret_val;
}

//void REVOKE(int ret_val, struct handle *handle);
//#define REVOKE(rd, rs2) ROCC_INSTRUCTION_DSS(2, rd, 0, rs2, 4);
int __REVOKE(const struct handle *handle) {
    int tmp_ret_val;
    ROCC_INSTRUCTION_DSS(2, tmp_ret_val, 0, handle, 4);
    return tmp_ret_val;
}

#endif /* KV_MOCK */


int WRAPKEY(struct wrap_data *handle_attrs, struct handle *handle) {
#ifdef KV_MOCK
    return MOCK_WRAPKEY(handle_attrs, handle);
#else
    return __WRAPKEY(handle_attrs, handle);
#endif
}

int ENCRYPT(struct io_struct *aes_io, const struct handle *handle) {
#ifdef KV_MOCK
    return MOCK_ENCRYPT(aes_io, handle);
#else
    return __ENCRYPT(aes_io, handle);
#endif
}

int DECRYPT(struct io_struct *aes_io, const struct handle *handle) {
#ifdef KV_MOCK
    return MOCK_DECRYPT(aes_io, handle);
#else
    return __DECRYPT(aes_io, handle);
#endif
}

int LOADCPUKEY(uint64_t key_low, uint64_t key_high) {
#ifdef KV_MOCK
    return MOCK_LOADCPUKEY(key_low, key_high);
#else
    return __LOADCPUKEY(key_low, key_high);
#endif
}

int REVOKE(const struct handle *handle) {
#ifdef KV_MOCK
    return MOCK_REVOKE(handle);
#else
    return __REVOKE(handle);
#endif
}


kv_status_t kv_get_status(int retVal) {
    switch(retVal) {
        case 0:
            return KV_SUCCESS;
        default:
            return KV_IO_FAIL;
    }
}

/* Additional Wrappers (needed?) */

kv_status_t kv_ins_wrap_key(kv_wrap_t *in_handle_attributes, kv_handle_t *out_handle) {
    int ret_val = 1;
    ret_val = WRAPKEY(in_handle_attributes, out_handle);
    return (kv_status_t) ret_val;
}

kv_status_t kv_ins_load_cpukey(uint64_t key_low, uint64_t key_high) {
    int ret_val = 1;
    ret_val = LOADCPUKEY(key_low, key_high);
    // note: return value of 2 means that an existing key got replaced
    if (ret_val == 2) return KV_SUCCESS_KEY_REPLACED;
    if (ret_val == 0) return KV_SUCCESS;
    return KV_IO_FAIL;
}

kv_status_t kv_ins_encrypt_data(kv_io_t *inout_aes_io, const kv_handle_t *in_handle) {
    int ret_val = 1;
    ret_val = ENCRYPT(inout_aes_io, in_handle);
    return kv_get_status(ret_val);
}

kv_status_t kv_ins_decrypt_data(kv_io_t *inout_aes_io, const kv_handle_t *in_handle) {
    int ret_val = 1;
    ret_val = DECRYPT(inout_aes_io, in_handle);
    return kv_get_status(ret_val);
}

kv_status_t kv_ins_revoke_handle(const kv_handle_t *in_handle) {
    int ret_val = 1;
    ret_val = REVOKE(in_handle);
    return kv_get_status(ret_val);
}

#ifdef __cplusplus
}
#endif

#endif /* __KEYVISOR_INSTRUCTIONS_H__ */