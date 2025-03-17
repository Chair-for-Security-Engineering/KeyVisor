#ifndef _EDGE_DEFINES_H_
#define _EDGE_DEFINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "channel_msg.h"
#include "keyvisor/handle.h"

#define OCALL_PRINT_BUFFER 1
#define OCALL_PRINT_VALUE 2
#define OCALL_SEND_REPORT 3
#define OCALL_WAIT_FOR_MESSAGE 4
#define OCALL_SEND_REPLY 5
#define OCALL_WAIT_FOR_SERVER_PUBKEY 6

#define OCALL_GET_CURRENT_FEATURE_UID 7
#define OCALL_PASS_LICENSE_DATA 8

//#define USE_OPENSSL_STUB_INSTEAD 1
#undef USE_OPENSSL_STUB_INSTEAD

typedef struct feature_license {
    int32_t usage_counter;

#ifdef USE_OPENSSL_STUB_INSTEAD
    uint8_t aes_128_key[16];
#else
    kv_handle_t ftr_khandle;
#endif
} ftr_license_t;

#ifdef __cplusplus
}
#endif

#endif /* _EDGE_DEFINES_H_ */