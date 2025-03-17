CC=riscv64-unknown-elf-gcc
OBJDMP=riscv64-unknown-elf-objdump
CFLAGS=-I.

SRC=.
BIN=build

FIRESIM_IMG_PATH=$(CONDA_DEFAULT_ENV)/../sw/firesim-software/images/firechip/br-base/br-base.img 

SRCS=$(wildcard $(SRC)/*.c)
BINS=$(SRCS:$(SRC)/%.c=%)

all: clean init $(BINS)

init:
	mkdir -p build/temp/
	mkdir -p build/asm/

%: %.c
# Bare Metal bins
	$(CC) -Iinclude -c -fno-common -fno-builtin-printf -specs=htif_nano.specs -o $(BIN)/temp/$@_bare.o $^
	$(CC) -Iinclude -static -specs=htif_nano.specs $(BIN)/temp/$@_bare.o -o $(BIN)/$@_bare
	$(OBJDMP) -drwC $(BIN)/$@_bare > $(BIN)/asm/$@_bare
# For Firesim
	$(CC) -Iinclude -c -fno-common -fno-builtin-printf -o $(BIN)/temp/$@.o $^
	$(CC) -Iinclude -static $(BIN)/temp/$@.o -o $(BIN)/$@
	$(OBJDMP) -drwC $(BIN)/$@ > $(BIN)/asm/$@

deploy: all
	sudo mount -o loop $(FIRESIM_IMG_PATH) /mnt
	sudo cp -r $(BIN) /mnt/home
	sudo umount /mnt

clean:
	rm -rf build