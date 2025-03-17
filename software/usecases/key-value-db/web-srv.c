#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>

//#define KV_MOCK 1
#undef KV_MOCK
#include "keyvisor/handle.h"
#include "keyvisor/instructions.h"

#include "keyvisor/key-handle-helpers.h"
#include "keyvisor/debug_handle.h"

#include "messages.pb-c.h"

#include "shared/usock-connection.h"
#include "shared/utils.h"

#include "external/handle_pb_prefix.h"

/// @brief request value of key from key-value service
/// @param cli_fd active connection to server
/// @param storage_key
/// @param out_buf
/// @param out_buf_len
/// @return 0 on success, else -1 (result written into out_buf)
int query_value(int cli_fd, void *storage_key, size_t key_len, void *out_buf, size_t *out_buf_len) {
    // Send read query request
    uint8_t io_buf[4096];
    ssize_t n_io;

    MsgProto__DataReadRequest req = MSG_PROTO__DATA_READ_REQUEST__INIT;
    req.storage_key.data = storage_key;
    req.storage_key.len = key_len;

    size_t req_len = msg_proto__data_read_request__get_packed_size(&req);
    uint8_t req_prfx_len = calc_prefix_len(req_len);

    write_varint(io_buf, sizeof(io_buf), req_len);
    msg_proto__data_read_request__pack(&req, &io_buf[req_prfx_len]);

    n_io = send(cli_fd, io_buf, req_prfx_len + req_len, 0);
    if (n_io < (req_prfx_len + req_len)) {
        printf("Sending full data read request message failed (sent: %ld)\n", n_io);
        return -1;
    }


    // Receiving handle response
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
    MsgProto__DataReadResponse *msg = msg_proto__data_read_response__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming data-read response\n");
        return -1;
    }
    if (msg->status == MSG_PROTO__REQUEST_STATUS__REQUEST_FAILED) {
        printf("Server sent FAILED response status back\n");
        msg_proto__data_read_response__free_unpacked(msg, NULL);
        return -1;
    }

    if (!msg->value_blob.data) {
        printf("Server replied with no value\n");
        msg_proto__data_read_response__free_unpacked(msg, NULL);
        return -1;
    } else {
        printf("Server replied with value\n");
    }
    if (msg->value_blob.len > *out_buf_len) {
        printf("Server response bigger than receive buffer\n");
        msg_proto__data_read_response__free_unpacked(msg, NULL);
        return -1;
    }

    memcpy(out_buf, msg->value_blob.data, msg->value_blob.len);
    *out_buf_len = msg->value_blob.len;
    msg_proto__data_read_response__free_unpacked(msg, NULL);

    return 0;
}

/// @brief Submit value to remote server
/// @param cli_fd
/// @param storage_key
/// @param value_buffer
/// @param value_len
/// @return 0 on success, else -1
int submit_data_write(int cli_fd, void *storage_key, size_t key_len, void *value_buffer, size_t value_len) {
    // Send data write request
    uint8_t io_buf[4096];
    ssize_t n_io;

    MsgProto__DataWriteRequest req = MSG_PROTO__DATA_WRITE_REQUEST__INIT;
    req.storage_key.data = storage_key;
    req.storage_key.len = key_len;
    req.value_blob.data = value_buffer;
    req.value_blob.len = value_len;

    size_t req_len = msg_proto__data_write_request__get_packed_size(&req);
    uint8_t req_prfx_len = calc_prefix_len(req_len);

    write_varint(io_buf, sizeof(io_buf), req_len);
    msg_proto__data_write_request__pack(&req, &io_buf[req_prfx_len]);

    n_io = send(cli_fd, io_buf, req_prfx_len + req_len, 0);
    if (n_io < (req_prfx_len + req_len)) {
        printf("Sending full data write request message failed (sent: %ld)\n", n_io);
        return -1;
    }


    // Receiving response
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
    MsgProto__DataWriteResponse *msg = msg_proto__data_write_response__unpack(NULL, result.prefix, msg_start);
    if (!msg) {
        printf("Failed unpacking incoming response\n");
        return -1;
    }
    if (msg->status == MSG_PROTO__REQUEST_STATUS__REQUEST_FAILED) {
        printf("Server sent FAILED response status back\n");
        msg_proto__data_write_response__free_unpacked(msg, NULL);
        return -1;
    } else {
        printf("Write submission to server was SUCCESSFUL\n");
        msg_proto__data_write_response__free_unpacked(msg, NULL);
        return 0;
    }
}


int main() {
    /* Start */
    printf("Starting web server (simplified):\n");

    /* (1) Generate key, create self-bound handle, wipe plaintext key */

    // dummy key used to encrypt values before submitting to key-value server
    // we currently support 128bit AES (=16B)
    uint64_t dummy_aes_128_key[2];
    dummy_aes_128_key[0] = 0xAFFEAFFEAFFEAFFE; // low
    dummy_aes_128_key[1] = 0xAFFEAFFEAFFEAFFE; // high

    // create self-bound handle (only usable within this process)
    kv_handle_t *kv_key_handle = kv_create_key_handle_ext(dummy_aes_128_key, KV_PERMIT_DECRYPT|KV_PERMIT_ENCRYPT, 0, KV_SELF_BIND);
    if (!kv_key_handle) {
        printf("Failed deriving self-bound handle\n");
        return EXIT_FAILURE;
    }
    print_handle(kv_key_handle);

    // wipe plaintext key
    memset(dummy_aes_128_key, 0, sizeof(dummy_aes_128_key));

    /* ---------- */

    /* (2) Prepare key-value: print data, GCM-encrypt data, key as AAD */
    uint8_t storage_key[] = { 's', 'e', 's', 's', 'i', 'o', 'n' };
    uint8_t storage_data[] = { 'h', 'e', 'l', 'l', 'o', '.', '\n' };

    printf("Storage key: ");
    print_byte_array(storage_key, sizeof(storage_key));
    printf("Storage data: ");
    print_byte_array(storage_data, sizeof(storage_data));

    uint8_t non_padded_data_inout_buf[8];
    assert((sizeof(non_padded_data_inout_buf)-1) == sizeof(storage_data));

    uint8_t gcm_iv[12]; // AES-GCM (96 bits)

    // setup buffers for encryption (IV is an output field in our system)
    memset(non_padded_data_inout_buf, 0, sizeof(non_padded_data_inout_buf));
    memcpy(non_padded_data_inout_buf, storage_data, sizeof(storage_data));
    non_padded_data_inout_buf[7] = 255;

    kv_io_t encryption_io_data = {
        .data = non_padded_data_inout_buf,
        .len_data = sizeof(storage_data),

        .aad = storage_key,
        .len_aad = sizeof(storage_key),
    };

    print_io(&encryption_io_data);


    printf("8. Byte before encrypt: %#x\n", non_padded_data_inout_buf[7]);
    if (kv_ins_encrypt_data(&encryption_io_data, kv_key_handle) != KV_SUCCESS) {
        printf("Failed using self-bound handle to encrypt data buffer\n");
        free(kv_key_handle);
        return EXIT_FAILURE;
    }
    printf("8. Byte AFTER encrypt: %#x\n", non_padded_data_inout_buf[7]);
    print_io(&encryption_io_data);
    // copy output IV
    memcpy(&gcm_iv[0], &encryption_io_data.iv_low, 8);
    memcpy(&gcm_iv[8], &encryption_io_data.iv_high, 4);

    /* ---------- */

    /* (3) craft value := iv|tag|cipher (12B [96 bits] + 16B [128 bits] + data-len) */

    size_t value_len = sizeof(gcm_iv) + sizeof(encryption_io_data.tag) + encryption_io_data.len_data;
    uint8_t *kv_value = malloc(value_len * sizeof(uint8_t));
    if (!kv_value) {
        printf("Failed allocating value buffer of size: %lu\n", value_len);
        free(kv_key_handle);
        return EXIT_FAILURE;
    }

    // copy iv, tag, cipher into value buffer
    memcpy(kv_value, gcm_iv, sizeof(gcm_iv));
    memcpy(&kv_value[sizeof(gcm_iv)], encryption_io_data.tag, sizeof(encryption_io_data.tag));
    memcpy(&kv_value[sizeof(gcm_iv)+sizeof(encryption_io_data.tag)],
        encryption_io_data.data, encryption_io_data.len_data);

    printf("crafted value: ");
    print_byte_array(kv_value, value_len);

    /* ---------- */

    /* (4) Submit (key, value) to keyvalue-server */

    printf("Connecting to key-value server\n");
    int cli_sock = kv_create_client_socket();
    if (cli_sock < 0) {
        printf("Failed client socket setup\n");
        free(kv_value);
        free(kv_key_handle);
        return EXIT_FAILURE;
    }
    printf("Succesfully connected\n");

    // Submit cipher to consumer service
    if (submit_data_write(cli_sock, storage_key, sizeof(storage_key), kv_value, value_len) < 0) {
        printf("Failed submitting (key, value) to key-value service\n");
        close(cli_sock);
        free(kv_value);
        free(kv_key_handle);
        return EXIT_FAILURE;
    }

    printf("Succesfully submitted (key, value) pair!\n");

    /* ---------- */

    /* (5) Query value with key from keyvalue-server */

    if (query_value(cli_sock, storage_key, sizeof(storage_key), kv_value, &value_len) < 0) {
        printf("Failed querying value for key from service\n");
        close(cli_sock);
        free(kv_value);
        free(kv_key_handle);
        return EXIT_FAILURE;
    }
    assert(value_len > (sizeof(gcm_iv) + sizeof(encryption_io_data.tag)));

    printf("queried value: ");
    print_byte_array(kv_value, value_len);

    printf("Succesfully queried value for key!\n");

    /* ---------- */

    /* (6) Parse value (iv|tag|cipher), GCM-decrypt it (AAD: key), print data */

    memset(non_padded_data_inout_buf, 0, sizeof(non_padded_data_inout_buf));
    memcpy(non_padded_data_inout_buf, &kv_value[sizeof(gcm_iv)
        + sizeof(encryption_io_data.tag)],
        value_len - sizeof(gcm_iv) - sizeof(encryption_io_data.tag));
    non_padded_data_inout_buf[7] = 4;

    assert((sizeof(non_padded_data_inout_buf)-1) == (value_len - sizeof(gcm_iv) - sizeof(encryption_io_data.tag)));

    kv_io_t decryption_io_data = {
        .data = non_padded_data_inout_buf,
        .len_data = sizeof(non_padded_data_inout_buf)-1,

        .aad = storage_key,
        .len_aad = sizeof(storage_key),
    };
    // for decrypt operation, IV is an input parameter
    memcpy(&decryption_io_data.iv_low, kv_value, 8);
    memset(&encryption_io_data.iv_high, 0, 8);
    memcpy(&decryption_io_data.iv_high, &kv_value[8], 4);
    // tag for verification
    memcpy(&decryption_io_data.tag[0], &kv_value[12], 8);
    memcpy(&decryption_io_data.tag[1], &kv_value[20], 8);

    print_io(&decryption_io_data);

    printf("8. Byte before decrypt: %#x\n", non_padded_data_inout_buf[7]);

    if (kv_ins_decrypt_data(&decryption_io_data, kv_key_handle) != KV_SUCCESS) {
        printf("GCM decryption of received value failed (corrupt cipher/data/iv/aad?)\n");
        close(cli_sock);
        free(kv_value);
        free(kv_key_handle);
        return EXIT_FAILURE;
    }
    printf("8. Byte AFTER decrypt: %#x\n", non_padded_data_inout_buf[7]);

    printf("Successful parsing + decryption of received value\n");

    printf("Queried key: ");
    print_byte_array(storage_key, sizeof(storage_key));

    printf("Decrypted data (TODO: includes padding): ");
    print_byte_array(non_padded_data_inout_buf, value_len - sizeof(gcm_iv) - sizeof(encryption_io_data.tag));

    /* ---------- */

    /* Finish */
    close(cli_sock);
    free(kv_value);
    free(kv_key_handle);
    return EXIT_SUCCESS;
}
