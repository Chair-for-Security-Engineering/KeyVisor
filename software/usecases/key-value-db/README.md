# Use Case 1: Web Server using a Key-Value Storage Server (simplified)
This use case models a web server using an untrusted key-value database to store data (cf. paper sections 2 and 6.3.1).
The data is locally encrypted using a key handle before submitting the data to the kv-database.
The key handle is bound to the web server process to protect it against leakage by co-located attacker processes.
The web server and kv-database communicate via UNIX domain sockets.

## Workflow
Simplified web server generates key, creates self-bound handle, encrypts data (with key as AAD), connects to key-value server, and submits (key, value:= iv|tag|cipher) for storage.

Then, web server retrieves value from key-value server via key, verify-decrypts it, and prints the retrieved (key, value).

TODO:
- currently a hardcoded dummy key is wrapped as protected key handle


## Building
Requires protobuf-c library to be installed for the communication between the web server and kv-database (https://github.com/protobuf-c/protobuf-c).

You need to source `env.sh` of Chipyard before trying to compile.


### With Make
building:
```
make -f Makefile-RISCV
```

deploying (you might have to adapt the image path):
```
make -f Makefile-RISCV deploy
```

cleaning:
```
make -f Makefile-RISCV clean
```

updating the protobuf files:
```
protoc --c_out=. ./messages.proto
```


## Running
Before running, make sure you issued the LOADCPUKEY KeyVisor instruction to load a visor key.

First run key-value server `./keyvalue-srv`, then web server `./web-srv`.

UNIX domain socket is currently created in `/tmp/kv_usecase_socket`.
