#include "tcp-connection.h"

#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#include <unistd.h>
#include <assert.h>

const char *KV_SRV_SOCK_IP = "172.16.0.1"; // not at FPGA (!= NIDS use case)
const uint16_t KV_SRV_SOCK_PORT = 4712;

int kv_create_tcp_server_socket(void) {
    printf("Create server socket\n");

    int srv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_sock < 0) {
        printf("Failed creating server socket\n");
        return srv_sock;
    }

    in_addr_t srv_in_addr = inet_addr(KV_SRV_SOCK_IP);
    struct sockaddr_in sock_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(KV_SRV_SOCK_PORT),
        .sin_addr = {.s_addr=srv_in_addr},
    };

    setsockopt(srv_sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    if (bind(srv_sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        printf("Failed binding server socket\n");
        close(srv_sock);
        return -1;
    }

    if (listen(srv_sock, 5) < 0) {
        printf("Failed listen on server socket\n");
        close(srv_sock);
        return -1;
    }

    return srv_sock;
}

int kv_create_tcp_client_socket(void) {
    printf("Create client socket\n");

    int cli_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (cli_sock < 0) {
        printf("Failed creating client socket\n");
        return cli_sock;
    }

    in_addr_t srv_in_addr = inet_addr(KV_SRV_SOCK_IP);
    struct sockaddr_in sock_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(KV_SRV_SOCK_PORT),
        .sin_addr = {.s_addr=srv_in_addr},
    };

    if (connect(cli_sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        printf("Failed connecting client to server socket\n");
        close(cli_sock);
        return -1;
    }

    return cli_sock;
}