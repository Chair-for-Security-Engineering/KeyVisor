# Use Case 2: Car licensing scheme / activation (simplified)
This use case models a car licensing scheme where customers can buy usage-limited access to extra features (cf. paper sections 2 and 6.3.2).

The use case depends on RISC-V Keystone support, and the communication channel is based on the Keystone Demo code.

## Components
The use case includes the gateway hosting a driving module (`driving_module`) thread and the client licensing Keystone enclave (`cli_license_enclave`), the motor unit (`motor_unit`), and the remote vendor service (`vendor_service`).

Note that the licensing enclave forms KeyVisor's secure Remote Key Provisioner in this use case.

The vendor service is meant to run on a remote x86 system, while the other processes are expected to run on the RISC-V FPGA.

## Workflow
The gateway service will start the driving module, which will request a feature license via the client licensing enclave.
The enclave will connect to the remote vendor service using a secure channel based on remote attestation + key exchange (using libsodium, cf. Keystone Demo), and receive the license key.
The enclave will then transform the key into a usage-limited key handle using KeyVisor and share it with the driving module thread (via shared memory).

The driving module will then contact the motor unit via UNIX domain sockets to request a nonce, sign the nonce, and send the resulting feature activation request back to the motor unit for verification.
The communication protocol is based on Google protobuf.

TODO:
- the vendor service does not check the attestation by default, but it has a flag ("--check-enclave-valid") to enable this functionality as provided by the Keystone Demo; please check the Keystone Demo to see how to set up the reference hash accordingly
- the feature-specific key is derived based on a hard-coded shared key (between vendor service and motor unit)


## Building
Requires protobuf-c library to be installed for the communication between the driving module and motor unit (https://github.com/protobuf-c/protobuf-c).

### Gateway with driving module ++ Keystone enclave
Source `env.sh` of Chipyard and make sure your RISC-V toolchain is used, and the paths in `scripts/deploy-car-gateway.sh` point to your (Firesim) image file.

Then simply run `./build-deploy-car-gw-riscv.sh`.

Deployed to `/mnt/home/car-gateway` on the FPGA.

### Motor unit
Source `env.sh`, then run `./build-motor-unit.sh` to build (and deploy).
Deployed to `/mnt/home/` on the FPGA.


### Vendor Service
The vendor service is built for x86, not RISC-V.
It requires the respective Keystone headers/libraries to be compiled for x86 in order to support parsing of the attestation report.

Follow the instructions in `keystone-sdk-x86.md` to perform the x86 Keystone build.

Then you should be able to build the remote vendor service by running `./build-vendor-x86.sh`.



## Running
Before running, make sure you issued the LOADCPUKEY KeyVisor instruction to load a visor key.

First run the motor unit on the FPGA (`./motor_unit`).
Then the remote vendor service (on local service, `./vendor_service/build/vendor_service`) --- make sure that the Chipyard/Firesim tap interface is up on `172.16.0.1`.
Finally, run the gateway service with enclave on the FPGA (`./car_gateway_and_cli.ke`).
