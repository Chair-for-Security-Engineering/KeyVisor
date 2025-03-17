#include <iostream>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>

#include "bus_communication.h"

#include "external/handle_pb_prefix.h"
#include "../include/print-utils.h"

extern "C" {
    #include "../car-bus-msg.pb-c.h"
}


// generate nonce, send nonce back
int request_feature_nonce(int srv_sock, int32_t feature_uid, uint8_t *out_nonce, size_t *inout_nonce_size) {
    assert(out_nonce && inout_nonce_size && *inout_nonce_size>0);
    uint8_t io_buf[4096];
    ssize_t n_io;

    // query challenge nonce for feature enabling
    CarBusMsgProto__InitFeatureRequest req = CAR_BUS_MSG_PROTO__INIT_FEATURE_REQUEST__INIT;
    req.feature_uid = feature_uid;

    size_t req_len = car_bus_msg_proto__init_feature_request__get_packed_size(&req);
    uint8_t req_prfx_len = calc_prefix_len(req_len);

    write_varint(io_buf, sizeof(io_buf), req_len);
    car_bus_msg_proto__init_feature_request__pack(&req, &io_buf[req_prfx_len]);

    n_io = send(srv_sock, io_buf, req_prfx_len + req_len, 0);
    if (n_io < (req_prfx_len + req_len)) {
        printf("Sending nonce request failed (sent: %ld)\n", n_io);
        return -1;
    }


    // receive nonce response
    n_io = recv(srv_sock, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read motor unit reply's protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    CarBusMsgProto__InitFeatureResponse *resp_msg = car_bus_msg_proto__init_feature_response__unpack(NULL, result.prefix, msg_start);
    if (!resp_msg) {
        printf("Failed unpacking incoming feature initialization response\n");
        return -1;
    }

    if (resp_msg->status != CAR_BUS_MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        printf("Querying nonce failed, received error response\n");
        car_bus_msg_proto__init_feature_response__free_unpacked(resp_msg, NULL);
        return -1;
    }

    printf("Server challenge nonce: ");
    print_byte_array(resp_msg->req_nonce.data, resp_msg->req_nonce.len);

    if (resp_msg->req_nonce.len > *inout_nonce_size) {
        printf("Cannot fit nonce in buffer\n");
        car_bus_msg_proto__init_feature_response__free_unpacked(resp_msg, NULL);
        return -1;
    }

    memcpy(out_nonce, resp_msg->req_nonce.data, resp_msg->req_nonce.len);
    *inout_nonce_size = resp_msg->req_nonce.len;

    car_bus_msg_proto__init_feature_response__free_unpacked(resp_msg, NULL);

    return 0;
}


int send_feature_enable_request(int srv_sock, const uint8_t *token, size_t tokenlen, const uint8_t *iv, size_t ivlen, const uint8_t *tag, size_t taglen) {
    assert(token && (tokenlen > 0) && iv && (ivlen == 12) && tag && (taglen == 16));

    uint8_t io_buf[4096];
    ssize_t n_io;

    // send authentication token to request feature enabling for this powercycle
    CarBusMsgProto__ActivateFeatureRequest req = CAR_BUS_MSG_PROTO__ACTIVATE_FEATURE_REQUEST__INIT;
    
    // TODO: will it free buffers, i.e., assume its owernship transfer?!
    req.auth_token.data = (uint8_t *)token;
    req.auth_token.len = tokenlen;
    req.token_iv.data = (uint8_t *)iv;
    req.token_iv.len = ivlen;
    req.token_tag.data = (uint8_t *)tag;
    req.token_tag.len = taglen;

    size_t req_len = car_bus_msg_proto__activate_feature_request__get_packed_size(&req);
    uint8_t req_prfx_len = calc_prefix_len(req_len);

    write_varint(io_buf, sizeof(io_buf), req_len);
    car_bus_msg_proto__activate_feature_request__pack(&req, &io_buf[req_prfx_len]);

    n_io = send(srv_sock, io_buf, req_prfx_len + req_len, 0);
    if (n_io < (req_prfx_len + req_len)) {
        printf("Sending feature-enable request failed (sent: %ld)\n", n_io);
        return -1;
    }


    // receive status response
    n_io = recv(srv_sock, io_buf, sizeof(io_buf), 0);
    if (n_io < 0) {
        perror("Receive error");
        return -1;
    }

    uint8_t *msg_start;
    prefix_res_t result;
    result = read_pb_prefix(io_buf, n_io, &msg_start);
    if(!result.success) {
        printf("Failed to read motor unit reply's protobuf prefix\n");
        return -1;
    }

    // Unpack new message into malloc() region (NULL->system alloactor)
    CarBusMsgProto__ActivateFeatureResponse *resp_msg = car_bus_msg_proto__activate_feature_response__unpack(NULL, result.prefix, msg_start);
    if (!resp_msg) {
        printf("Failed unpacking incoming feature-enable response\n");
        return -1;
    }

    if (resp_msg->status != CAR_BUS_MSG_PROTO__REQUEST_STATUS__REQUEST_SUCCESS) {
        printf("Feature-activation request has been denied by the motor unit\n");
    } else {
        printf("Feature-activation request has been GRANTED by the motor unit\n");
        printf("Feature can now be used until next powercycle.\n");
    }

    car_bus_msg_proto__activate_feature_response__free_unpacked(resp_msg, NULL);

    return 0;
}