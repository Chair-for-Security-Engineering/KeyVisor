#include <iostream>
#include <unistd.h>
#include <pthread.h>

#include "keysrv_host.h"
#include "traffic_decryptor.h"


int main(int argc, char** argv) {
  /* Start keyserver (with enclave) in separate thread */
  pthread_t keyserver_thread;
  if (pthread_create(&keyserver_thread, NULL, key_server_main, NULL) != 0) {
    std::cerr << "failed creating key server host thread" << std::endl;
    return EXIT_FAILURE;
  }

  perform_traffic_decryption();

  pthread_join(keyserver_thread, NULL); // TODO: stop signal
  return EXIT_SUCCESS;
}
