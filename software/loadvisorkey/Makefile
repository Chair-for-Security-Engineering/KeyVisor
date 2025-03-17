CC=riscv64-unknown-linux-gnu-gcc
OBJDMP=riscv64-unknown-elf-objdump
CFLAGS=-I.

SRC=.
BIN=build

FIRESIM_IMG_PATH=$(CONDA_DEFAULT_ENV)/../software/firemarshal/images/keystone.img 

SRCS=$(wildcard $(SRC)/*.c)
BINS=$(SRCS:$(SRC)/%.c=%)

all: clean init $(BINS)

init:
	mkdir -p build/temp/
	mkdir -p build/asm/

%: %.c
# For Firesim
	$(CC) -Iinclude -c -fno-common -fno-builtin-printf -o $(BIN)/temp/$@.o $^ $(LDFLAGS)
	$(CC) -Iinclude -static $(BIN)/temp/$@.o -o $(BIN)/$@ $(LDFLAGS)
	$(OBJDMP) -drwC $(BIN)/$@ > $(BIN)/asm/$@

deploy: all
	sudo mount -o loop $(FIRESIM_IMG_PATH) /mnt
	sudo rm -rf /mnt/home/keyvisor
	sudo mkdir -p /mnt/home/keyvisor
	sudo cp -r $(BIN) /mnt/home/keyvisor
	sudo umount /mnt

clean:
	rm -rf build
