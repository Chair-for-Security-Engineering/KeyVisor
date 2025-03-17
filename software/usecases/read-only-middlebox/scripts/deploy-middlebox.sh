FIRESIM_IMG_PATH="${CONDA_DEFAULT_ENV}/../software/firemarshal/images/keystone.img"

sudo mount -o loop ${FIRESIM_IMG_PATH} /mnt || exit 1
sudo rm -rf /mnt/home/ro-middlebox
sudo mkdir -p /mnt/home/ro-middlebox
sudo cp -r ./build/ro_middlebox.ke /mnt/home/ro-middlebox
sudo umount /mnt
