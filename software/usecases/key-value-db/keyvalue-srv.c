#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>

#include <sys/socket.h>

#include <signal.h>

#include <string.h>

//#define KV_MOCK 1
#undef KV_MOCK
#include "keyvisor/handle.h"
#include "keyvisor/instructions.h"

#include "messages.pb-c.h"

#include "include/kv-storage.h"
#include "shared/usock-connection.h"
#include "keyvisor/key-handle-helpers.h"

#include "external/handle_pb_prefix.h"

static volatile int keepListening = 1;

/// @brief tell server loop to stop on sigint
/// @param unused 
void intSigHandler(int unused) {
    (void)unused;
    keepListening = 0;
}

/// @brief Receive value query for key frmo client, send back stored value.
/// @param cli_fd active socket connection to client
/// @return 0 on success, else -1
int process_data_read_request(int cli_fd) {
    // Wait for write-handle query request
    uint8_t io_buf[4096];
    ssize_t n_io;

    n_io = recv(cli_fd, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    MsgProto__DataReadRequest *msg = msg_proto__data_read_request__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming data read request\n");
        return -1;
    }
    printf("Client requested value for storage key: ");
    for(size_t i=0; i<msg->storage_key.len; i++)
        printf("%#x ", msg->storage_key.data[i]);
    printf("\n");

    // Check DB for value to send it back
    MsgProto__DataReadResponse resp = MSG_PROTO__DATA_READ_RESPONSE__INIT;

    s_key_t query_key = {
        .key_len = msg->storage_key.len,
        .key = msg->storage_key.data,
    };

    uint8_t value_buffer[128];
    size_t value_len = sizeof(value_buffer);

    if(kv_read_from_stub_storage(query_key, value_buffer, &value_len) < 0) {
        printf("Failed retrieving value for key\n");
        resp.status = MSG_PROTO__REQUEST_STATUS__REQUEST_FAILED;
    } else {
        printf("Successfully retrieved value for key\n");
        resp.status = MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS;
    }

    // key no longer needed
    msg_proto__data_read_request__free_unpacked(msg, NULL);


    resp.value_blob.len = value_len;
    resp.value_blob.data = value_buffer;

    size_t resp_len = msg_proto__data_read_response__get_packed_size(&resp);
    uint8_t resp_prfx_len = calc_prefix_len(resp_len);

    write_varint(io_buf, sizeof(io_buf), resp_len);
    msg_proto__data_read_response__pack(&resp, &io_buf[resp_prfx_len]);

    n_io = send(cli_fd, io_buf, resp_prfx_len + resp_len, 0);
    if (n_io < (resp_prfx_len + resp_len)) {
        printf("Sending full value response back failed (sent: %ld)\n", n_io);
        return -1;
    }

    return 0;
}

/// @brief Receive (key, value) storage request from client.
/// @param cli_fd active socket connection to client
/// @return 0 on success, else -1
int process_data_write_request(int cli_fd) {
    // Wait for data write query request
    uint8_t io_buf[4096];
    ssize_t n_io;

    n_io = recv(cli_fd, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    MsgProto__DataWriteRequest *msg = msg_proto__data_write_request__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming data write request\n");
        return -1;
    }
    printf("Client requested value storage for key: ");
    for(size_t i=0; i<msg->storage_key.len; i++)
        printf("%#x ", msg->storage_key.data[i]);
    printf("\n");

    MsgProto__RequestStatus status;

    // pass the (key, value) pair to the stub storage
    s_key_t new_key = {
        .key_len = msg->storage_key.len,
        .key = msg->storage_key.data,
    };

    if (kv_write_to_stub_storage(new_key, msg->value_blob.data, msg->value_blob.len) < 0) {
        printf("Failed submission to storage\n");
        status = MSG_PROTO__REQUEST_STATUS__REQUEST_FAILED;
    } else {
        status = MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS;
    }

    msg_proto__data_write_request__free_unpacked(msg, NULL);


    // Send response back to client
    MsgProto__DataWriteResponse resp = MSG_PROTO__DATA_WRITE_RESPONSE__INIT;
    resp.status = status;

    size_t resp_len = msg_proto__data_write_response__get_packed_size(&resp);
    uint8_t resp_prfx_len = calc_prefix_len(resp_len);

    write_varint(io_buf, sizeof(io_buf), resp_len);
    msg_proto__data_write_response__pack(&resp, &io_buf[resp_prfx_len]);

    n_io = send(cli_fd, io_buf, resp_prfx_len + resp_len, 0);
    if (n_io < (resp_prfx_len + resp_len)) {
        printf("Sending full data write response back failed (sent: %ld)\n", n_io);
        return -1;
    }

    return 0;
}


int main() {
    printf("Starting key-value service:\n");

    struct sigaction int_stopper;
    memset(&int_stopper, 0, sizeof(int_stopper));
    int_stopper.sa_handler = intSigHandler;
    if (sigaction(SIGINT, &int_stopper, NULL) < 0) {
        printf("Failed setting up sigint handler\n");
        return EXIT_FAILURE;
    }

    if (kv_init_stub_storage()) {
        printf("Failed initing stub storage\n");
        return EXIT_FAILURE;
    }

    int srv_sock = kv_create_server_socket();
    if (srv_sock < 0) {
        printf("Failed creating server socket\n");
        kv_destroy_stub_storage();
        return EXIT_FAILURE;
    }

    while (keepListening) {
        printf("Listening for client ...\n");
        int cli_fd = accept(srv_sock, NULL, NULL);
        if (cli_fd < 0) {
            perror("Failed accepting client");
            continue;
        }
        printf("Accepted client\n");

        // Note: simplified, non-robust recv/send (e.g., not partial recv loop, no out-of-order reequests/replies)

        // Wait for data write request
        if (process_data_write_request(cli_fd) < 0) {
            printf("Failed receiving (key, value)\n");
            close(cli_fd);
            continue;
        }
        printf("Stored (key, value) pair\n");


        // Wait for key query request
        if (process_data_read_request(cli_fd) < 0) {
            printf("Failed receiving client key\n");
            close(cli_fd);
            continue;
        }
        printf("Received client key, sent back stored value from storage\n");

        printf("Closing client connection\n");
        close(cli_fd);
    } 

    close(srv_sock);
    unlink(KV_SRV_SOCK_PATH);
    kv_destroy_stub_storage();
    return EXIT_SUCCESS;
}
