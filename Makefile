UNAME := $(shell uname)

XTENSA_TOOLCHAIN := "xtensa-esp32-elf-linux64-1.22.0-61-gab8375a-5.2.0.tar.gz"

ifeq ($(UNAME), Darwin)
XTENSA_TOOLCHAIN := "xtensa-esp32-elf-osx-1.22.0-61-gab8375a-5.2.0.tar.gz"
endif

fmt:
	clang-format -i ./*.c ./*.h -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i ./test/main/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120}"

test/xtensa-esp32-elf:
	wget https://dl.espressif.com/dl/$(XTENSA_TOOLCHAIN)
	cd test; tar -xzf ../$(XTENSA_TOOLCHAIN)
	rm *.tar.gz

test/esp-idf:
	git clone --recursive --depth 1 https://github.com/espressif/esp-idf.git test/esp-idf

build: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make

flash:
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make flash

monitor:
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make monitor

run: build flash monitor
