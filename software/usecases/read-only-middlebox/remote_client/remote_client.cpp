#include <string.h>
#include "remote_client.h"
#include "client_main.h"

#include "test_dev_key.h"
#include "enclave_expected_hash.h"
#include "sm_expected_hash.h"

#include "tls_session_data.h"


unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char client_sk[crypto_kx_SECRETKEYBYTES];
unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
unsigned char rx[crypto_kx_SESSIONKEYBYTES];
unsigned char tx[crypto_kx_SESSIONKEYBYTES];

int double_fault;
int channel_ready;

void remote_client_exit(){
  if(double_fault || !channel_ready){
    printf("DC: Fatal error, exiting. Remote not cleanly shut down.\n");
    exit(-1);
  }
  else{
    double_fault = 1;
    printf("[TC] Exiting. Attempting clean remote shutdown.\n");
    send_exit_message();
    exit(0);
  }
}

/* init libsodium and create client key pair */
void remote_client_init(){
  if( sodium_init() != 0){
    printf("[TC] Libsodium init failure\n");
    remote_client_exit();
  }
  if( crypto_kx_keypair(client_pk,client_sk) != 0){
    printf("[TC] Libsodium keypair gen failure\n");
    remote_client_exit();
  }

  channel_ready = 0;
}

byte* remote_client_pubkey(size_t* len){
  *len = crypto_kx_PUBLICKEYBYTES;
  return (byte*)client_pk;
}

/* Parse enclave report from buffer, verify it, extract the server public key 
 * into the (global) server_pk variable, and then calculate two shared session keys
 * one for receiving (global rx variable), one for sending (global tx variable) */
void remote_client_get_report(void* buffer, int ignore_valid){
  Report report;
  report.fromBytes((unsigned char*)buffer);
#ifdef REMOTE_CLIENT_DEBUG_PRINTS
  report.printPretty();
#endif

  if (report.verify(enclave_expected_hash,
  		    sm_expected_hash,
  		    _sanctum_dev_public_key)) {
#ifdef REMOTE_CLIENT_DEBUG_PRINTS
    printf("[TC] Attestation signature and enclave hash are valid\n");
#endif
  } else {
#ifdef REMOTE_CLIENT_DEBUG_PRINTS
    printf("[TC] Attestation report is NOT valid\n");
#endif
    if( ignore_valid ) {
#ifdef REMOTE_CLIENT_DEBUG_PRINTS
      printf("[TC] Ignore Validation was set, CONTINUING WITH INVALID REPORT\n");
#endif
    } else {
      remote_client_exit();
    }
  }

  if(report.getDataSize() !=  crypto_kx_PUBLICKEYBYTES) {
    printf("[TC] Bad report data sec size\n");
    remote_client_exit();
  }

  // extract server public key from report
  memcpy(server_pk, report.getDataSection(), crypto_kx_PUBLICKEYBYTES);

  // calculate two shared session keys (rx, tx)
  if(crypto_kx_client_session_keys(rx, tx, client_pk, client_sk, server_pk) != 0) {
    printf("[TC] Bad session keygen\n");
    remote_client_exit();
  }

#ifdef REMOTE_CLIENT_DEBUG_PRINTS
  printf("[TC] Session keys established\n");
#endif
  channel_ready = 1;
}

#define MSG_BLOCKSIZE 32
#define BLOCK_UP(len) (len+(MSG_BLOCKSIZE - (len%MSG_BLOCKSIZE)))

/* Perform authenticated encryption of msg with session key (tx) via libsodium
 *
 * result buffer is of `*finalsize` and includes cipher, tag, and nonce */
byte* remote_client_box(byte* msg, size_t size, size_t* finalsize) {
  size_t size_padded = BLOCK_UP(size);
  *finalsize = size_padded + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
  byte* buffer = (byte*)malloc(*finalsize);
  if(buffer == NULL) {
    printf("[TC] NOMEM for msg\n");
    remote_client_exit();
  }

  memcpy(buffer, msg, size);

  size_t buf_padded_len;
  if (sodium_pad(&buf_padded_len, buffer, size, MSG_BLOCKSIZE, size_padded) != 0) {
    printf("[TC] Unable to pad message, exiting\n");
    remote_client_exit();
  }

  // create random nonce for auth-encryption
  unsigned char* nonceptr = &(buffer[crypto_secretbox_MACBYTES+buf_padded_len]);
  randombytes_buf(nonceptr, crypto_secretbox_NONCEBYTES);

  if(crypto_secretbox_easy(buffer, buffer, buf_padded_len, nonceptr, tx) != 0) {
    printf("[TC] secretbox failed\n");
    remote_client_exit();
  }

  return(buffer);
}

/* Perform verify-decrypt of buffer with session key (rx) via libsodium */
void remote_client_unbox(unsigned char* buffer, size_t len) {
  size_t clen = len - crypto_secretbox_NONCEBYTES;
  unsigned char* nonceptr = &(buffer[clen]);
  if (crypto_secretbox_open_easy(buffer, buffer, clen, nonceptr, rx) != 0) {
    printf("[TC] unbox failed\n");
    remote_client_exit();
  }

  size_t ptlen = len - crypto_secretbox_NONCEBYTES - crypto_secretbox_MACBYTES;
  size_t unpad_len;
  if( sodium_unpad(&unpad_len, buffer, ptlen, MSG_BLOCKSIZE) != 0) {
    printf("[TC] Invalid message padding, ignoring\n");
    remote_client_exit();
  }

  return;
}


/* creates + sends exit request */
void send_exit_message() {
  size_t pt_size;
  channel_message_t* pt_msg = generate_exit_message(&pt_size);

  size_t ct_size;
  byte* ct_msg = remote_client_box((byte*)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);
}


void send_session_data_message(session_data_t *buffer) {
  if (!buffer) return;

  size_t pt_size;
  channel_message_t *pt_msg = generate_session_data_message((uint8_t *) buffer, get_session_data_size(buffer->num_keys), &pt_size);

  size_t ct_size;
  byte* ct_msg = remote_client_box((byte*)pt_msg, pt_size, &ct_size);

  send_buffer(ct_msg, ct_size);

  free(pt_msg);
  free(ct_msg);
}


/* create EXIT request message (to finish session) */
channel_message_t* generate_exit_message(size_t* finalsize) {
  channel_message_t* message_buffer = (channel_message_t*)malloc(sizeof(channel_message_t));
  message_buffer->msg_type = CHANNEL_MSG_EXIT;
  message_buffer->len = 0;

  *finalsize = sizeof(channel_message_t);

  return message_buffer;
}

channel_message_t* generate_session_data_message(uint8_t* buffer, size_t buffer_len, size_t* finalsize) {
  channel_message_t* message_buffer = (channel_message_t*)malloc(buffer_len+sizeof(channel_message_t));

  message_buffer->msg_type = CHANNEL_MSG_SESSION_DATA;
  message_buffer->len = buffer_len;
  memcpy(message_buffer->msg, buffer, buffer_len);

  *finalsize = buffer_len + sizeof(channel_message_t);

  return message_buffer;
};
