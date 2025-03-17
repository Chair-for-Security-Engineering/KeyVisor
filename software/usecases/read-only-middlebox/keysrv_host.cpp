#include <iostream>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include "keystone.h"
#include "edge_wrapper.h"
#include "encl_message.h" // TODO: mostly unused

#include <keyvisor/debug_handle.h>

#include <arpa/inet.h>

#include "keysrv_host.h"
#include "sess_info_db.h"
#include "print-utils.h"

#define PRINT_MESSAGE_BUFFERS 1

/* We hardcode these for demo purposes. */
const char* enc_path = "keysrv_enclave.eapp_riscv";
const char* runtime_path = "eyrie-rt";

#define PORTNUM 8067
int fd_clientsock;  // socket of client connection (when accepted)
#define BUFFERLEN 4096
byte local_buffer[BUFFERLEN];

void init_network_wait();

/* Send (len||buffer) via socket to client */
void send_buffer(byte* buffer, size_t len){
  write(fd_clientsock, &len, sizeof(size_t));
  write(fd_clientsock, buffer, len);
}

/* Receive (msg-len||msg) via socket from client */
byte* recv_buffer(size_t* len) {
  read(fd_clientsock, local_buffer, sizeof(size_t));
  size_t reply_size = *(size_t*)local_buffer;
  byte* reply = (byte*)malloc(reply_size);

  read(fd_clientsock, reply, reply_size);
  *len = reply_size;
  return reply;
}

// debug printing
void print_hex_data(unsigned char* data, size_t len) {
  unsigned int i;
  std::string str;

  for(i=0; i<len; i+=1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)data[i];
    str += ss.str();

    if(i>0 && (i+1)%8 == 0) {
      if((i+1)%32 == 0) {
	      str += "\n";
      } else {
	      str += " ";
      }
    }
  }

  printf("%s\n\n",str.c_str());
}


/* ---- START of OCALLs (edge calls) ---- */

// OCALL_PRINT_BUFFER (print_buffer_wrapper)
unsigned long print_buffer(char* str) {
  printf("[SE] %s",str);
  return strlen(str);
}

// OCALL_PRINT_VALUE (print_value_wrapper)
void print_value(unsigned long val) {
  printf("[SE] value: %#x\n",val);
  return;
}

// OCALL_SEND_REPLY (send_reply_wrapper)
void send_reply(void* data, size_t len) {
  printf("[EH] Sending encrypted reply:\n");

  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)data, len);

  send_buffer((byte*)data, len);
}

// OCALL_WAIT_FOR_CLIENT_PUBKEY (wait_for_client_pubkey_wrapper)
void* wait_for_client_pubkey() {
  size_t len;
  return recv_buffer(&len);
}

// OCALL_WAIT_FOR_MESSAGE (wait_for_message_wrapper)
encl_message_t wait_for_message() {
  size_t len;

  void* buffer = recv_buffer(&len);

  printf("[EH] Got an encrypted message:\n");
  if( PRINT_MESSAGE_BUFFERS ) print_hex_data((unsigned char*)buffer, len);

  /* This happens here */
  encl_message_t message;
  message.host_ptr = buffer;
  message.len = len;
  return message;
}

// OCALL_SEND_REPORT (send_report_wrapper)
void send_report(void* buffer, size_t len) {
  send_buffer((byte*)buffer, len);
}

// OCALL_PASS_SESSION_KEY_BUNDLE (pass_key_handle_wrapper)
void pass_key_handle(sess_kbundle_t *sess_key_bundle) {
  // debug print session key handle
  printf("Received %lu handles:\n", sess_key_bundle->num_handles);
  for (size_t i=0; i<sess_key_bundle->num_handles; i++) {
    assert(sizeof(sess_key_bundle->sess_handles[i].handshake_iv_tls12) == 4);
    printf("handshake IV: ");
    print_byte_array(sess_key_bundle->sess_handles[i].handshake_iv_tls12, 4);
    print_handle((kv_handle_t *)&sess_key_bundle->sess_handles[i].handle);
  }

  // debug print associated connection info
  struct in_addr client_ip = {.s_addr=sess_key_bundle->conn_info.client_ip};
  struct in_addr server_ip = {.s_addr=sess_key_bundle->conn_info.server_ip};
  printf("Connection info:\n%s:%hu --> ", inet_ntoa(client_ip),
    ntohs(sess_key_bundle->conn_info.client_port));
  printf("%s:%hu\n", inet_ntoa(server_ip),
    ntohs(sess_key_bundle->conn_info.server_port));

  // create copy for entry, because data is in shared memory atm
  skbndl_entry_t new_entry = {
    .conn_info = sess_key_bundle->conn_info,
  };
  new_entry.sess_handle_vec.reserve(sess_key_bundle->num_handles);
  for (size_t i=0; i<sess_key_bundle->num_handles; i++) {
    new_entry.sess_handle_vec.push_back(sess_key_bundle->sess_handles[i]);
  }

  // TODO: will this copy again?
  session_info_map[sess_key_bundle->conn_info].push_front(std::move(new_entry));

  printf("Entries for this connection in DB: %lu\n", session_info_map[sess_key_bundle->conn_info].size());
}

// OCALL_WAIT_FOR_TCP_CLIENT
void wait_for_tcp_client() {
  printf("HOST: Gonna wait for incoming connection by remote client before starting the enclave.\n");

  /* Wait for network incoming client connection (TCP/IP) */
  init_network_wait();

  printf("[EH] Got connection from remote client\n");
}

/* ---- END of OCALLs (edge calls) ---- */


/* Create TCP/IP server socket at ANY:<PORTNUM>, accept incoming client connection,
 * store resulting client connection socket in global varable `fd_clientsock` */
void init_network_wait() {
  int fd_sock;
  struct sockaddr_in server_addr;

  fd_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_sock < 0){
    printf("Failed to open socket\n");
    exit(-1);
  }

  int en = 1;
  setsockopt(fd_sock, SOL_SOCKET, SO_REUSEADDR, &en, sizeof(int));

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(PORTNUM);
  if( bind(fd_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
    printf("Failed to bind socket\n");
    exit(-1);
  }
  listen(fd_sock,2);

  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  fd_clientsock = accept(fd_sock, (struct sockaddr*)&client_addr, &client_len);
  if (fd_clientsock < 0){
    printf("No valid client socket\n");
    exit(-1);
  }

  // TODO: fd_sock neither closed nor saved for reuse?!
}

void *key_server_main(void *arg) {
  Keystone::Enclave enclave;
  Keystone::Params params;

  /* Setup and call into enclave */
  if(enclave.init(enc_path, runtime_path, params) != Keystone::Error::Success){
    printf("HOST: Unable to start enclave\n");
    exit(-1);
  }

  edge_init(&enclave);

  Keystone::Error rval = enclave.run();
  printf("rval: %i\n",rval);

  return NULL;
}
