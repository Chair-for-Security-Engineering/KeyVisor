#include "usock-connection.h"

#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <string.h>

#include <unistd.h>
#include <assert.h>

const char *KV_SRV_SOCK_PATH = "/tmp/kv_usecase_socket";

int kv_create_server_socket(void) {
    printf("Create server socket\n");

    int srv_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_sock < 0) {
        printf("Failed creating server socket\n");
        return srv_sock;
    }

    struct sockaddr_un sock_addr = {
        .sun_family = AF_UNIX,
    };
    assert((strlen(KV_SRV_SOCK_PATH)+1) <= sizeof(sock_addr.sun_path));
    strncpy(sock_addr.sun_path, KV_SRV_SOCK_PATH, sizeof(sock_addr.sun_path));

    if (bind(srv_sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        printf("Failed binding server socket\n");
        close(srv_sock);
        unlink(KV_SRV_SOCK_PATH);
        return -1;
    }

    if (listen(srv_sock, 5) < 0) {
        printf("Failed listen on server socket\n");
        close(srv_sock);
        unlink(KV_SRV_SOCK_PATH);
        return -1;
    }

    return srv_sock;
}

int kv_create_client_socket(void) {
    printf("Create client socket\n");

    int cli_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_sock < 0) {
        printf("Failed creating client socket\n");
        return cli_sock;
    }

    struct sockaddr_un sock_addr = {
        .sun_family = AF_UNIX,
    };
    assert((strlen(KV_SRV_SOCK_PATH)+1) <= sizeof(sock_addr.sun_path));
    strncpy(sock_addr.sun_path, KV_SRV_SOCK_PATH, sizeof(sock_addr.sun_path));



    if (connect(cli_sock, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
        printf("Failed connecting client to server socket\n");
        close(cli_sock);
        return -1;
    }

    return cli_sock;
}
