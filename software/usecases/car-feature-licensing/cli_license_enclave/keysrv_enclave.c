#include "app/eapp_utils.h"
#include "string.h"
#include "syscall.h"
#include "malloc.h"
#include "edge_wrapper.h"
#include "sodium.h"
#include "hacks.h"

#include "channel.h"
#include "channel_msg.h"

#include "khandles.h"


/* create report with server public key embedded, send to client, wait for client's
 * public key, then derive two shared sessions keys (rx, tx) */
void attest_and_establish_channel() {
  // TODO sizeof report
  char buffer[2048];
  attest_enclave((void*) buffer, client_pk, crypto_kx_PUBLICKEYBYTES);
  ocall_send_report(buffer, 2048);

  ocall_wait_for_server_pubkey(server_pk, crypto_kx_PUBLICKEYBYTES);
  channel_establish();
}

/* receive client requests and handle them until client requests EXIT */
int perform_license_request(int32_t feature_uid) {
  struct edge_data msg;

  // send license request
  if (channel_send_license_query_message(feature_uid) != 0) {
    ocall_print_buffer("Failed to send license query to vendor server\n");
    return -1;
  }

  // receive feature license (server will close socket afterwards)
  ocall_wait_for_message(&msg);
  channel_message_t* channel_msg = malloc(msg.size);
  size_t msg_len;

  if(channel_msg == NULL) {
    ocall_print_buffer("Server message too large to store, aborting\n");
    return -1;
  }

  copy_from_shared(channel_msg, msg.offset, msg.size);
  // verify-decrypt
  if(channel_recv((unsigned char*)channel_msg, msg.size, &msg_len) != 0) {
    free(channel_msg);
    ocall_print_buffer("Failed decrypt-verify of server response\n");
    return -1;
  }

  int ret_val;
  switch(channel_msg->msg_type) {
    /* Received EXIT message from client, so shutdown */
    case CHANNEL_MSG_EXIT: {
      ocall_print_buffer("Server requested exit, i.e., something went wrong\n");
      ret_val = -1;
      break;
    }

    case CHANNEL_MSG_LICENSE_DATA: {
      if (handle_feature_license(channel_msg->msg, channel_msg->len) != 0) {
        ocall_print_buffer("Failed wrapping feature key\n");
        ret_val = -1;
      } else {
        ret_val = 0;
      }
      break;
    }

    default: {
      ocall_print_buffer("Received unknown/unexpected server message type (%hu)\n");
      ret_val = -1;
      break;
    }
  }

  // Done with the message, free it
  free(channel_msg);

  return ret_val;
}

/* main entry point of enclave */
void EAPP_ENTRY eapp_entry() {
  edge_init(); // OCALLs
  magic_random_init(); // randomness

  // try to get current feature uid
  struct edge_data msg;
  ocall_get_current_feature_uid(&msg);
  int32_t feature_uid;
  if (msg.size != sizeof(feature_uid)) {
    ocall_print_buffer("feature UID has unexpected length:\n");
    ocall_print_value(msg.size);
    return;
  }
  copy_from_shared((uint8_t *)&feature_uid, msg.offset, msg.size);

  ocall_print_buffer("Trying to establish attest-encrypted channel with connected remote server.\n");
  channel_init(); // init libsodium, generate client key pair
  /* generate report, send it to server, wait for public key msg from server,
   * and then generate the two shared session keys (rx, tx) */
  attest_and_establish_channel();

  if (perform_license_request(feature_uid) != 0) {
    ocall_print_buffer("Failed receiving feature license.\n");
    EAPP_RETURN(1);
  }

  EAPP_RETURN(0);
}