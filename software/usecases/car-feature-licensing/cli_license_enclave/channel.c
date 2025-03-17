#include "eapp_utils.h"
#include "sodium.h"
#include "channel.h"
#include "string.h"
#include "edge_wrapper.h"

unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

channel_message_t *generate_license_query_message(uint8_t *buffer, size_t buffer_len, size_t *finalsize);

void channel_init() {
  /* libsodium config */
  randombytes_set_implementation(&randombytes_salsa20_implementation);

  if(sodium_init() < 0 ){
    ocall_print_buffer("[C] Sodium init failed, exiting\n");
    EAPP_RETURN(1);
  }

  /* Generate our keys */
  if(crypto_kx_keypair(client_pk, client_sk) != 0){
    ocall_print_buffer("[C] Unable to generate keypair, exiting\n");
    EAPP_RETURN(1);
  }
}

void channel_establish() {
  /* Ask libsodium to generate session keys based on the recv'd pk */
  if(crypto_kx_server_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
    ocall_print_buffer("[C] Unable to generate session keys, exiting\n");
    EAPP_RETURN(1);
  }
  ocall_print_buffer("[C] Successfully generated session keys.\n");
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

/* verify+decrypt msg_buffer; strip tag, nonce, and padding from plaintext msg
 *
 * msg_buffer will start with unpadded plaintext message of `*datalen` */
int channel_recv(unsigned char* msg_buffer, size_t len, size_t* datalen) {
  /* We store the nonce at the end of the ciphertext buffer for easy
     access */
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(msg_buffer[clen]);

  if (crypto_secretbox_open_easy(msg_buffer, msg_buffer, clen, nonceptr, rx) != 0){
    ocall_print_buffer("[C] Invalid message, ignoring\n");
    return -1;
  }
  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;

  size_t unpad_len;
  if( sodium_unpad(&unpad_len, msg_buffer, ptlen, MSG_BLOCKSIZE) != 0){
    ocall_print_buffer("[C] Invalid message padding, ignoring\n");
    return -1;
  }

  *datalen = unpad_len;

  return 0;
}


/* Perform authenticated encryption of msg with session key (tx) via libsodium
 *
 * result buffer is of `*finalsize` and includes cipher, tag, and nonce */
uint8_t *crypto_channel_box(uint8_t* msg, size_t size, size_t* finalsize) {
  size_t size_padded = BLOCK_UP(size);
  *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
  uint8_t *buffer = (uint8_t *)malloc(*finalsize);
  if(buffer == NULL) {
    ocall_print_buffer("[TC] NOMEM for msg\n");
    return NULL;
  }

  memcpy(buffer, msg, size);

  size_t buf_padded_len;
  if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
    ocall_print_buffer("[TC] Unable to pad message, exiting\n");
    free(buffer);
    return NULL;
  }

  // create random nonce for auth-encryption
  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0) {
    ocall_print_buffer("[TC] secretbox failed\n");
    free(buffer);
    return NULL;
  }

  return(buffer);
}

/* Perform verify-decrypt of buffer with session key (rx) via libsodium */
int crypto_channel_unbox(unsigned char* buffer, size_t len) {
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(buffer[clen]);
  if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0) {
    ocall_print_buffer("[TC] unbox failed\n");
    return -1;
  }

  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  size_t unpad_len;
  if( sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0) {
    ocall_print_buffer("[TC] Invalid message padding, stopping\n");
    return -1;
  }

  return 0;
}

int channel_send_license_query_message(int32_t feature_uid) {
  size_t pt_size;
  channel_message_t *pt_msg = generate_license_query_message((uint8_t *) &feature_uid, sizeof(feature_uid), &pt_size);

  size_t ct_size;
  uint8_t* ct_msg = crypto_channel_box((uint8_t *)pt_msg, pt_size, &ct_size);

  if (!ct_msg) return -1;

  ocall_send_reply(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);

  return 0;
}

channel_message_t *generate_license_query_message(uint8_t *buffer, size_t buffer_len, size_t *finalsize) {
  channel_message_t* message_buffer = (channel_message_t*)malloc(buffer_len+sizeof(channel_message_t));

  message_buffer->msg_type = CHANNEL_MSG_QUERY_LICENSE;
  message_buffer->len = buffer_len;
  memcpy(message_buffer->msg, buffer, buffer_len);

  *finalsize = buffer_len + sizeof(channel_message_t);

  return message_buffer;
};