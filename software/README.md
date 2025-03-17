# KeyVisor Software

The `include` folder contains header files that define the instructions and data types needed by KeyVisor.
In particular, take a look at `include/keyvisor/handle.h` and `include/keyvisor/instructions.h`.

If you define `KV_MOCK` at compile time, the KeyVisor instructions will be replaced with empty stubs. 
This allows you to test your code before running it on the RocketChip.

Chipyard automatically installs the RISC-V toolchain needed to compile the sources.
Make sure you source `env.sh` before attempting to compile the binaries. 
Once sourced, simply run make in the demo folder to compile the binaries.


## Demo Workload for KeyVisor
The demo workload generates random input, which is then encrypted and later decrypted using KeyVisor.
The tool also checks the correctness of the authentication tag. 
For instructions how to run RocketChip with KeyVisor, see the hardware part of the repo. 
When using KeyVisor with Verilator, execute the binary `build/enc_dec_demo_bare`. Otherwise (when using FireSim), use `build/enc_dec_demo`.
If everything is correct, the output should look like this:

```
+ Started KeyVisor Demo
+ Creating Key Handle
+ Testing Encryption    1 / 1 Data Len: 4, AAD Len: 4
        + Encryption done; IV: bfe7476a 500fd5f7d47c2a10; 
                CT: c2 bb 2a 3d 
                GCM Auth Tag: bf 95 f6 2b 
        + Decryption done.
                PT: ff fe fd fc 
        + Test Successful, decrypted plaintext is correct and tags match.
+++ All tests finished successfully! +++
```


## Load Visor Key
A simple binary for loading a development/demo visor key is provided in `loadvisorkey`.
The use cases expect a visor key to be set up before execution.

## Use Cases
The use cases described in sections 2 and 6.3 of the paper are located in `./usecases/`.

