#ifndef _CHANNEL_MSG_H_
#define _CHANNEL_MSG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h> // size_t

// currently sent by enclave as reply to key wrapping (msg_session_data)
#define CHANNEL_SIMPLE_ACK 2082

#define CHANNEL_MSG_EXIT 1
#define CHANNEL_MSG_SESSION_DATA 2

/* message types send from client to server/enclave
 *
 * are auth-encrypted with session keys via libsodium, and then send as (len||cbox),
 * where cbox contains cipher, tag, and nonce as required for verify-decrypt
 *
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