#!/bin/bash
pushd motor_unit
rm -rf build
mkdir -p build
pushd build
cmake -DCMAKE_TOOLCHAIN_FILE=../../../riscv-br-toolchain.cmake -DCMAKE_BUILD_TYPE="Debug" ..
make
popd
popd

####### deploy

FIRESIM_IMG_PATH="${CONDA_DEFAULT_ENV}/../software/firemarshal/images/keystone.img"

sudo mount -o loop ${FIRESIM_IMG_PATH} /mnt || exit 1
sudo mkdir -p /mnt/home/
sudo cp ./motor_unit/build/motor_unit /mnt/home/
sudo umount /mnt


exit 0
