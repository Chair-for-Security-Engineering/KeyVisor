#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <iostream>
#include <fstream>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <arpa/inet.h>

#include "remote_client.h"
#include "client_main.h"

#include "tls_session_data.h"

#include "print-utils.h"


extern "C" {
    #include "tls_session_data.h"
}


#define PORTNUM 8067

int fd_sock;
struct sockaddr_in server_addr;
struct hostent *server;

#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

/* send message to server/enclave (len||msg), |len| = sizeof(size_t) bytes */
void send_buffer(byte* buffer, size_t len) {
  write(fd_sock, &len, sizeof(size_t));
  write(fd_sock, buffer, len);
}

/* receive message from server/enclave (len||msg), |len| = sizeof(size_t) bytes */
byte* recv_buffer(size_t* len) {
  ssize_t n_read = read(fd_sock, local_buffer, sizeof(size_t));
  if(n_read != sizeof(size_t)){
    // Shutdown
    printf("[TC] Invalid message header\n");
    remote_client_exit();
  }
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);
  if(reply == NULL){
    // Shutdown
    printf("[TC] Message too large\n");
    remote_client_exit();
  }
  n_read = read(fd_sock, reply, reply_size);
  if(n_read != reply_size){
    printf("[TC] Bad message size\n");
    // Shutdown
    remote_client_exit();
  }

  *len = reply_size;
  return reply;
}


int share_tls_keys(const char *hostname, bool ignore_valid_flag,
  const unsigned char *cli_tx_key, const unsigned char *cli_rx_key, size_t keylen,
  const unsigned char *cli_tx_iv, const unsigned char *cli_rx_iv, size_t ivlen,
  uint16_t src_port, uint16_t dst_port, uint32_t src_ip, uint32_t dst_ip) {

  // we currently assume TLS 1.2, AES-GCM (AEAD)
  assert(ivlen == 4);

  int ignore_valid = 0;
  if (ignore_valid_flag) {
    ignore_valid = 1;
  }

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if(fd_sock < 0){
    printf("No socket\n");
    exit(-1);
  }
  server = gethostbyname(hostname);
  if(server == NULL) {
    printf("Can't get host\n");
    exit(-1);
  }
  server_addr.sin_family = AF_INET;
  memcpy(&server_addr.sin_addr.s_addr,server->h_addr,server->h_length);
  server_addr.sin_port = htons(PORTNUM);

  // Connect via TCP/IP to remote server
  if( connect(fd_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    printf("Can't connect\n");
    exit(-1);
  }

#ifdef REMOTE_CLIENT_DEBUG_PRINTS
  printf("[TC] Connected to enclave host!\n");
#endif

  /* Establish crypto channel (TCP already established above) */
  remote_client_init();
  
  size_t report_size;
  // receive initial msg with report
  byte* report_buffer = recv_buffer(&report_size);
  // parse report, verify it, extract srv public key, calculate session keys (rx, tx)
  remote_client_get_report(report_buffer, ignore_valid);
  free(report_buffer);

  /* Send client pubkey to server/enclave */
  size_t pubkey_size;
  byte* pubkey = remote_client_pubkey(&pubkey_size); // get reference to it
  send_buffer(pubkey, pubkey_size); // send it

  // session data message (CHANNEL_MSG_SESSION_DATA)
  sess_data_crafter_t *sess_craft = prepare_session_data(src_port, dst_port, src_ip, dst_ip, 2);
  assert(sess_craft);

  if (add_session_key(sess_craft, client_encrypt, cli_tx_iv, ivlen, cli_tx_key
, keylen) != SC_NO_ERROR) {
    printf("Failed adding client TX key\n");
    free_unfinished_session_crafter(sess_craft);
    send_exit_message();
    close(fd_sock);
    exit(-1);
  }

  if (add_session_key(sess_craft, server_encrypt, cli_rx_iv, ivlen, cli_rx_key, keylen) != SC_NO_ERROR) {
    printf("Failed adding client RX (server) key\n");
    free_unfinished_session_crafter(sess_craft);
    send_exit_message();
    close(fd_sock);
    exit(-1);
  }

  session_data_t *sess_data;
  if (finalize_session_data(sess_craft, &sess_data) != SC_NO_ERROR) {
    printf("Failed finalizing session data\n");
    free_unfinished_session_crafter(sess_craft);
    send_exit_message();
    close(fd_sock);
    exit(-1);
  }
  assert(sess_data);
  sess_craft = NULL;

  send_session_data_message(sess_data);

  // synchronous: wait for ACK by enclave, such that we know that the keys have been successfully added to the DB, and monitoring is ready to go; -- it is just an encrypted integer at the moment, nothing special
  size_t reply_size;
  byte *reply = recv_buffer(&reply_size);
  assert(reply);
  remote_client_unbox(reply, reply_size);
  int* replyval = (int*)reply;
  if (*replyval == CHANNEL_SIMPLE_ACK) {
#ifdef REMOTE_CLIENT_DEBUG_PRINTS
    printf("Received ACK from enclave\n");
#endif
  } else {
    printf("Error: wrong ACK from enclave\n");
    free(reply);
    close(fd_sock);
    exit(-1);
  }
  free(reply);

  // we won't send more keys, so close
  send_exit_message();
  close(fd_sock);
  return 0;
}