# Keystone-SDK for x86, how to:

1. `git clone https://github.com/keystone-enclave/keystone-sdk keystone-sdk-x86`

2. `cd keystone-sdk-x86; git checkout 24a5ed369ac0606aac486382a0855a459d9362ed`

3. apply the patch inside the keystone-sdk folder via `patch -p1 < ../patch-keystone-sdk-x86.patch`

4. `mkdir install-dir`

5. `mkdir build; cd build; KEYSTONE_SDK_DIR=`pwd`/../install-dir cmake ..; make; make install`
