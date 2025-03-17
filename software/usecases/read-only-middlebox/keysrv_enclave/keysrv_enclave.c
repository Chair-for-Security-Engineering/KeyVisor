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
  attest_enclave((void*) buffer, server_pk, crypto_kx_PUBLICKEYBYTES);
  ocall_send_report(buffer, 2048);

  ocall_wait_for_client_pubkey(client_pk, crypto_kx_PUBLICKEYBYTES);
  channel_establish();
}

/* receive client CALC requests and handle them until client requests EXIT */
void handle_messages() {
  struct edge_data msg;
  while(1) {
    ocall_wait_for_message(&msg);
    channel_message_t* channel_msg = malloc(msg.size);
    size_t msg_len;

    if(channel_msg == NULL) {
      ocall_print_buffer("Message too large to store, ignoring\n");
      continue;
    }

    copy_from_shared(channel_msg, msg.offset, msg.size);
    if(channel_recv((unsigned char*)channel_msg, msg.size, &msg_len) != 0) {
      free(channel_msg);
      continue;
    }

    switch(channel_msg->msg_type) {
      /* Received EXIT message from client, so shutdown */
      case CHANNEL_MSG_EXIT: {
        ocall_print_buffer("Received exit, exiting\n");
        EAPP_RETURN(0);
        break;
      }

      case CHANNEL_MSG_SESSION_DATA: {
        handle_session_keys(channel_msg->msg, channel_msg->len);

        /* Send simple number back as ACK that we finished key handling.
         * Otherwise, packets might arrive before we are set up. */
        int val = CHANNEL_SIMPLE_ACK;
        size_t reply_size = channel_get_send_size(sizeof(int));
        unsigned char* reply_buffer = malloc(reply_size);
        if (reply_buffer == NULL) {
          ocall_print_buffer("Reply too large to allocate, no reply sent\n");
          break;
        }
        channel_send((unsigned char*)&val, sizeof(int), reply_buffer);
        ocall_send_reply(reply_buffer,reply_size);
        free(reply_buffer);
        break;
      }

      default: {
        ocall_print_buffer("Received unknown message type (%hu)\n");
        break;
      }
    }

    // Done with the message, free it
    free(channel_msg);
  }
}

/* main entry point of enclave */
void EAPP_ENTRY eapp_entry() {
  edge_init(); // OCALLs
  magic_random_init(); // randomness

  ocall_wait_for_tcp_client();

  ocall_print_buffer("Wait for remote client to connect.\n");
  channel_init(); // init libsodium, generate server key pair
  /* generate report, send it to client, wait for public key msg from client,
   * and then generate the two shared session keys (rx, tx) */
  attest_and_establish_channel();

  handle_messages(); // wait for client CALC msg + handle it (endless loop until EXIT)

  EAPP_RETURN(0);
}