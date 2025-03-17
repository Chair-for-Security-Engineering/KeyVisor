FIRESIM_IMG_PATH="${CONDA_DEFAULT_ENV}/../software/firemarshal/images/keystone.img"

sudo mount -o loop ${FIRESIM_IMG_PATH} /mnt || exit 1
sudo rm -rf /mnt/home/car-gateway
sudo mkdir -p /mnt/home/car-gateway
sudo cp -r ./build/car_gateway_and_cli.ke /mnt/home/car-gateway
sudo umount /mnt
