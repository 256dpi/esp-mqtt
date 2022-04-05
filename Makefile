SHELL := /bin/bash

ESP_IDF_VERSION := "v4.4"

fmt:
	clang-format -i ./*.c ./*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i ./test/main/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"

prepare:
	git clone --recursive  https://github.com/espressif/esp-idf.git test/esp-idf
	cd test/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION)
	cd test/esp-idf/; git submodule update --recursive --init

update:
	cd test/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION)
	cd test/esp-idf/; git submodule update --recursive --init

install:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; cd test/esp-idf; ./install.sh esp32

defconfig:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; make defconfig

menuconfig:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; make menuconfig

erase:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; make erase_flash

clean:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; make clean

build:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; make

flash:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh;  cd test; make flash

monitor:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh;  cd test; make monitor

simple-monitor:
	@clear
	miniterm.py /dev/cu.SLAB_USBtoUART 115200 --rts 0 --dtr 0 --raw --exit-char 99

run: build flash monitor
