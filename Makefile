SHELL := /bin/bash

ESP_IDF_VERSION := "v5.1.1"

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

config:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py menuconfig

reconfigure:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py reconfigure
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py fullclean

erase:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py erase-flash

clean:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py clean

build:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py build

flash:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh;  cd test; idf.py flash

monitor:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh;  cd test; idf.py monitor

simple-monitor:
	@clear
	miniterm.py /dev/cu.SLAB_USBtoUART 115200 --rts 0 --dtr 0 --raw --exit-char 99

run: build flash monitor
