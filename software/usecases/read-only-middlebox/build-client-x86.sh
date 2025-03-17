#!/bin/bash
yes | rm -rf remote_client/build
#yes | rm -rf libsodium_builds/libsodium_client

echo "##############################################################"
echo "Prepare..."

# source keystone SDK environment
export KEYSTONE_SDK_DIR="`pwd`/keystone-sdk-x86/install-dir/"

# we just provide some value to silence the build atm
export SM_HASH="`pwd`/sm_expected_hash.h"

echo "##############################################################"
echo "Build..."
set -e

# Check location/tools
if [[ ! -v KEYSTONE_SDK_DIR ]]
then
    echo "KEYSTONE_SDK_DIR not set! Please set this to the location where Keystone SDK has been installed."
    exit 0
fi

if [[ ! -v SM_HASH ]]
then
    echo "SM_HASH is not set! Please follow README to generate the expected hash"
    exit 0
fi

DEMO_DIR=$(pwd)

set -e

mkdir -p libsodium_builds
cd libsodium_builds

# Clone, checkout, and build the client libsodium
if [ ! -d libsodium_client ]
then
  git clone https://github.com/jedisct1/libsodium.git libsodium_client
  cd libsodium_client
  git checkout 4917510626c55c1f199ef7383ae164cf96044aea
  ./configure --host=x86_64-linux-gnu --disable-ssp --disable-asm --without-pthreads
  make
  cd ..
fi
export LIBSODIUM_CLIENT_DIR=$(pwd)/libsodium_client/src/libsodium/

cd ..

# Copy the expected hash over
echo "Copying expected sm hash from riscv-pk, this may be incorrect!"
cp $SM_HASH include/

# Build the demo
pushd remote_client
mkdir -p build
pushd build
cmake -DCMAKE_BUILD_TYPE="Debug" ..
make
popd
popd

echo "##############################################################"
echo "Finished."
exit 0
