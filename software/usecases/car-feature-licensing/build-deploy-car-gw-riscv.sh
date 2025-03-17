#!/bin/bash
yes | rm -rf build
#yes | rm -rf libsodium_builds/libsodium_server

echo "##############################################################"
echo "Prepare..."

#pushd ~/chipyard/
#. ./env.sh || exit 1
#popd

# source keystone SDK environment
pushd ${CONDA_DEFAULT_ENV}/../software/firemarshal/firemarshal-keystone/keystone/
. source.sh
popd
# we just provide some value to silence the build atm
export SM_HASH="`pwd`/sm_expected_hash.h"

echo "##############################################################"
echo "Build..."
yes Y | ./scripts/build-car-gateway.sh || exit 1

echo "##############################################################"
echo "Deploy..."
yes Y | ./scripts/deploy-car-gateway.sh || exit 1

echo "##############################################################"
echo "Finished."
exit 0
