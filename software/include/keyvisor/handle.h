#ifndef __KEYVISOR_HANDLE_H__
#define __KEYVISOR_HANDLE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Usage Hints 
 * - for encrypt/decrypt, the data/cipher and AAD lengths must be a multiple the block cipher width, i.e., 128 bits (16 Bytes) at the moment; please pad accordingly;
 * - when enabling KV_SELF_BIND, you also must set KV_ENABLE_PE_BINDING
 * - when enabling KV_PMP_BIND, you also must set KV_ENABLE_PE_BINDING
 * - when setting a usage counter (counter >0), you must also set KV_ENABLE_USAGE_COUNTER
 * - KV_ENABLE_LIFETIME is currently not implemented
 * - If you use more than two handles that collide in the HCB, the handlegen fails currently. That is, since the swap is not implemented. Retrying will likely succeed since a new IV is chosen
*/


// Privileges
#define KV_PERMIT_PRIV_USER         0x1 // bit 0
#define KV_PERMIT_PRIV_SUPERVISOR   0x2 // bit 1
#define KV_PERMIT_PRIV_MACHINE      0x8 // bit 3

// Algorithm
#define KV_ALGORITHM_GCM  0x2

// Crypt. Attr.
#define KV_PERMIT_ENCRYPT 0x1
#define KV_PERMIT_DECRYPT 0x2

// Feature Map
#define KV_ENABLE_LIFETIME      0x1 // bit 0
#define KV_ENABLE_PE_BINDING    0x2 // bit 1
#define KV_ENABLE_USAGE_COUNTER 0x4 // bit 2

// Handle Flags
#define KV_SELF_BIND 0x40 // IF KV_ENABLE_PE_BINDING: Set to 1 if binding to the active process / enclave ELSE: None
#define KV_PMP_BIND  0x80 // IF KV_ENABLE_PE_BINDING: Set to 1 to bind to PMP region (TEE), 0 for SATP (Process) ELSE: None


// Struct used to create new handles
struct __attribute__ ((__packed__)) wrap_data{
    uint64_t AES_key[2];        // 0   ... 127  Data Key
    uint8_t privileges;         // 128 ... 135  Privileges            
    uint8_t aes_mode;           // 136 ... 143  Algorithm
    uint8_t usage_ctr;          // 144 ... 151  --- USAGE CTR (Will not be part of flags in the handle) ---
    uint8_t crypto_attributes;  // 152 ... 159  Crypt. Attr. 
    uint16_t exattr_map;        // 160 ... 175  Feature Map
    uint8_t ext_attr_flags;     // 176 ... 183  Handle Flags
    uint8_t reserved;           // 184 ... 191  -
    uint64_t lifetime_ticks;    // 192 ... 255  Select how many cycles the handle remains valid (not yet implemented)
    uint64_t pID;               // 256 ... 319  PID of the process to which the handle is bound. Requires KV_ENABLE_PE_BINDING = true, KV_SELF_BIND = false, KV_PMP_BIND = false
    uint8_t pmp_id;             // 320 ... 327  PMP ID of the process to which the handle is bound. Requires KV_ENABLE_PE_BINDING = true, KV_SELF_BIND = false, KV_PMP_BIND = true
    uint8_t reserved_2;         // 328 ... 335  -
    uint16_t reserved_3;        // 336 ... 351  - 
    uint32_t reserved_4;        // 352 ... 383  -
};

// Handle data structure
struct __attribute__ ((__packed__)) handle{
    uint8_t attr_flags;         // 0   ... 7    Handle Flags
    uint8_t privileges;         // 8   ... 15   Privileges
    uint8_t crypto_algo;        // 16  ... 23   Algorithm
    uint8_t crypto_attr;        // 24  ... 31   Crypt. Attr. 
    uint16_t exattr_map;        // 32  ... 47   Feature Map
    uint16_t reserved;          // 48  ... 63   -
    uint64_t timestamp;         // 64  ... 127  End of life timestamp (not yet implemented)
    uint64_t iv_low;            // 128 ... 191  IV of the handle, Low 64 Bit
    uint64_t iv_high;           // 192 ... 255  IV of the handle, High 32 Bit
    uint64_t AES_GCM_TAG[2];    // 256 ... 383  Handle Integrity Tag
    uint64_t AES_GCM_CT[2];     // 384 ... 511  Encrypted Data Key
};

// Data structre to de- and encrypt data
struct __attribute__ ((__packed__)) io_struct{
    uint64_t iv_low;            // 0   ... 63   IV of the data encryption, Low 64 Bit
    uint64_t iv_high;           // 64  ... 127  IV of the data encryption, High 32 Bit
    uint64_t tag[2];            // 128 ... 255  Integrity tag of the encryption
    uint8_t *aad;               // 256 ... 319  Pointer to AAD
    uint8_t *data;              // 320 ... 384  Pointer to Data
    uint32_t len_aad;           // 384 ... 415  Length of AAD
    uint32_t len_data;          // 416 ... 447  Length of Data
};

typedef struct handle kv_handle_t;
typedef struct wrap_data kv_wrap_t;
typedef struct io_struct kv_io_t;

#ifdef __cplusplus
}
#endif

#endif /* __KEYVISOR_HANDLE_H__ */
