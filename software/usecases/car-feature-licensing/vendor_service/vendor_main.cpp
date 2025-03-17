#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>

#include <iostream>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>

#include <openssl/hmac.h>

#include "vendor_service.h"
#include "vendor_main.h"

#include "../include/channel_msg.h"
#include "tcp-connection.h"
#include "../include/car_shared_key.h"

#include "print-utils.h"

#include <openssl/bio.h>
#include <openssl/evp.h>

#define PORTNUM 8067

int fd_clientsock, fd_srv;
struct sockaddr_in client_addr;

static volatile int keepListening = 1;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

/// @brief tell server loop to stop on sigint
/// @param unused 
void intSigHandler(int unused) {
  (void)unused;
  keepListening = 0;
}

bool derive_aes_feature_key(int32_t feature_uid, unsigned char *out_key, unsigned int *inout_keylen) {
  if (!out_key || !inout_keylen || (*inout_keylen < (unsigned int)EVP_MD_size(EVP_sha256())) ) {
    return false;
  }

  uint32_t data_buf = feature_uid;

  /* key := HMAC(car-key, feature-uid) */
  // TODO: do we need an 256 AES key for the HMAC?
  if (!HMAC(EVP_sha256(), shared_car_vendor_key_128aes, sizeof(shared_car_vendor_key_128aes), (uint8_t *)&data_buf, sizeof(data_buf), out_key, inout_keylen)) {
    return false;
  }

  return true;
}

/* send message to server/enclave (len||msg), |len| = sizeof(size_t) bytes */
void send_buffer(byte* buffer, size_t len) {
  write(fd_clientsock, &len, sizeof(size_t));
  write(fd_clientsock, buffer, len);
}

/* receive message from server/enclave (len||msg), |len| = sizeof(size_t) bytes */
byte* recv_buffer(size_t* len) {
  ssize_t n_read = read(fd_clientsock, local_buffer, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[TC] Invalid message header\n");
    vendor_service_exit();
  }
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    vendor_service_exit();
  }
  n_read = read(fd_clientsock, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    vendor_service_exit();
  }

  *len = reply_size;
  return reply;
}


int main(int argc, char *argv[])
{
  int ignore_valid = 1;
  if(argc >= 2){
    if(strcmp(argv[1],"--check-enclave-valid") == 0){
      ignore_valid = 0;
    }
  }

  struct sigaction int_stopper;
  memset(&int_stopper, 0, sizeof(int_stopper));
  int_stopper.sa_handler = intSigHandler;
  if (sigaction(SIGINT, &int_stopper, NULL) < 0) {
      printf("Failed setting up sigint handler\n");
      return EXIT_FAILURE;
  }

  fd_srv = kv_create_tcp_server_socket();
  if(fd_srv < 0) {
    printf("No server socket\n");
    exit(-1);
  }

  while (keepListening) {
    printf("[TC] Waiting for connection by enclave host (license client)!\n");

    socklen_t client_len = sizeof(client_addr);
    fd_clientsock = accept(fd_srv, (struct sockaddr*)&client_addr, &client_len);
    if (fd_clientsock < 0){
      perror("No valid client socket");
      close(fd_srv);
      exit(-1);
    }

    /* Establish crypto channel (TCP already established above) */
    vendor_service_init();
    
    size_t report_size;
    // receive initial msg with report
    byte* report_buffer = recv_buffer(&report_size);
    // parse report, verify it, extract srv public key, calculate session keys (rx, tx)
    vendor_service_get_report(report_buffer, ignore_valid);
    free(report_buffer);

    /* Send server pubkey to client/enclave */
    size_t pubkey_size;
    byte* pubkey = vendor_service_pubkey(&pubkey_size); // get reference to it
    send_buffer(pubkey, pubkey_size); // send it
    

    /* Next: wait for CHANNEL_MSG_QUERY_LICENSE */
    // Check if EXIT message, QUERY_LICENSE, or unknown garbage
    size_t out_cipher_len;
    channel_message_t *msg_buffer = (channel_message_t *)recv_buffer(&out_cipher_len);
    if (!msg_buffer) {
      printf("Failed receiving a message from client through crypted channel\n");
      send_exit_message();
      close(fd_clientsock);
      continue;
    }

    size_t out_plaintext_msg_len;
    if(channel_recv((unsigned char*)msg_buffer, out_cipher_len, &out_plaintext_msg_len) != 0) {
      printf("Failed decrypting client message\n");
      send_exit_message();
      close(fd_clientsock);
      continue;
    }

    switch(msg_buffer->msg_type) {
      /* Received EXIT message from client, so shutdown */
      case CHANNEL_MSG_EXIT: {
        printf("Client requested exit\n");
        close(fd_clientsock);
        continue;
      }

      case CHANNEL_MSG_QUERY_LICENSE: {
        if (msg_buffer->len < sizeof(int32_t)) {
          printf("Client message length too small\n");
          send_exit_message();
          close(fd_clientsock);
          continue;
        }

        license_t feature_license;
        feature_license.feature_uid = *((int32_t *)msg_buffer->msg);
        feature_license.usage_counter = 5;

        printf("feature uid: %d\n", feature_license.feature_uid);

        uint8_t ftr_aes_key[32]; // 256bits, bcs. HMAC uses sha-256
        unsigned int ftr_key_len = sizeof(ftr_aes_key);
        if (!derive_aes_feature_key(feature_license.feature_uid, ftr_aes_key, &ftr_key_len)) {
          printf("Failed deriving feature-specific AES key\n");
          send_exit_message();
          close(fd_clientsock);
          continue;
        }
        printf("resulting HMAC: "); print_byte_array(ftr_aes_key, ftr_key_len);
        // TODO: might not be secure to use only parts of hash? (not sure)
        assert(ftr_key_len >= 16);
        memcpy(feature_license.aes_128_key, ftr_aes_key, 16);
        printf("resulting feature key: "); print_byte_array(feature_license.aes_128_key, 16);

        send_license_data_message(&feature_license);
        printf("Sent license to client, shutting connection down\n");
        close(fd_clientsock);
        break;
      }

      default: {
        printf("Received unknown client message. Disconnecting\n");
        send_exit_message();
        close(fd_clientsock);
        continue;
      }
    }
}

  close(fd_srv);
  return EXIT_SUCCESS;
}
