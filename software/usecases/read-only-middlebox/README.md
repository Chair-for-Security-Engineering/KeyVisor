# Use Case 3: Read-only TLS Traffic Monitor
This use case models a traffic monitor that receives read-only access to the TLS traffic between a client and server in order to scan the plaintext traffic for attacks (cf. paper sections 2 and 6.3.3).

The use case depends on RISC-V Keystone support, and the communication channel is based on the Keystone Demo code.

## Components
The use case includes the middlebox with traffic monitor (`traffic_decryptor`) and key server enclave (`keysrv_enclave`), a TLS 1.2 remote client based on the mbedTLS client demo (`remote_client`), and a TLS 1.2 server based on the mbedTLS server demo (`ssl_server`).

Note that the key server enclave forms KeyVisor's secure Remote Key Provisioner in this use case.

The remote client is meant to run on a remote x86 system, while the other processes are expected to run on the RISC-V FPGA.

## Workflow
The client connects via TLS 1.2 (mbedTLS) to the server.
During the handshake (after the key exchange), the client connects to the key server enclave (hosted by the middlebox service) in order to share the connection data and keys (TLS uses one key per communication direction, i.e., two).
The enclave transforms the keys into KeyVisor decrypt-only key handles and shares them with the traffic monitor thread (via shared memory).
The traffic monitor uses libpcap to monitor the TCP traffic between client and server, trying to decrypt the TLS application data using the key handles.

The key-sharing hook during the TLS handshake is currently implemented using a custom key-export callback function for mbedTLS.

TODO:
- does not yet support decrypting handshake messages (relevant for TLS 1.3)
- the remote client does not check the attestation by default; the feature can e be enabled by updating the call to `share_tls_keys`; the functionality is available as provided by the Keystone Demo; please check the Keystone Demo to see how to set up the reference hash accordingly
- the connection metadata is currently received by the key server enclave, which would only be compatible with the Remote Key Provisioner concept if allowing for additional custom user data to be passed along the key + usage policy; alternatively, the use case prototype could be adjusted to send the connection metadata directly to the non-enclave host process of the middlebox monitor


## Building
Note that you probably will have to adjust the target IP of the remote client, which is used to connect to the TLS server and key server enclave.

Requires libpcap and libmbedtls.
There is an option to use an OpenSSL stub instead of the KeyVisor key handles (for testing), which is disabled by default (via a macro).

### Middlebox with traffic monitor ++ Keystone enclave
Source `env.sh` of Chipyard and make sure your RISC-V toolchain is used, and the paths in `scripts/deploy-middlebox.sh` point to your (Firesim) image file.

Then simply run `./build-deploy-mb-riscv.sh`.

Deployed to `/mnt/home/ro-middlebox` on the FPGA.

### TLS Server
Source `env.sh`, then run `./build-ssl-server.sh` to build (and deploy).
Deployed to `/mnt/home/` on the FPGA.


### (Remote) TLS Client
The remote TLS client is built for x86, not RISC-V.
It requires the respective Keystone headers/libraries to be compiled for x86 in order to support parsing of the attestation report.

Follow the instructions in `keystone-sdk-x86.md` to perform the x86 Keystone build.

Then you should be able to build the remote vendor service by running `./build-client-x86.sh`.



## Running
Before running, make sure you issued the LOADCPUKEY KeyVisor instruction to load a visor key.

First run the TLS server on the FPGA (`./ssl_server`).
Then the middlebox service hosting the traffic monitor and enclave on the FPGA (`./ro_middlebox.ke`).
Finally, run the remote TLS client, e.g., on the x86 server connected to the FPGA (`remote_client`)---remember to check the target IP to which the client connects.
