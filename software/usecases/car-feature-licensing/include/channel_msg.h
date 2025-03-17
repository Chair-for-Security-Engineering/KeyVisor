#ifndef _CHANNEL_MSG_H_
#define _CHANNEL_MSG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// enclave --> vendor
#define CHANNEL_MSG_QUERY_LICENSE 0x1
#define CHANNEL_MSG_EXIT 0x2

// enclave <-- vendor
#define CHANNEL_MSG_LICENSE_DATA 0x10

//typedef enum feature_uid {
//    SPORT_MODE,
//} ftr_uid_t;

typedef int32_t ftr_uid_t;

typedef struct license_data {
    ftr_uid_t feature_uid;
    uint32_t usage_counter;
    uint8_t aes_128_key[16];
} license_t;


/* message types send between enclave and vendor service
 *
 * are auth-encrypted with session keys via libsodium, and then send as (len||cbox),
 * where cbox contains cipher, tag, and nonce as required for verify-decrypt
 */
typedef struct channel_message_t {
  unsigned short msg_type;
  size_t len;
  char msg[]; // Flexible member
} channel_message_t;

#ifdef __cplusplus
}
#endif

#endif /* _CHANNEL_MSG_H_ */