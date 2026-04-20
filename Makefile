SHELL := /bin/bash

TARGET := "esp32s3"
ESP_IDF_VERSION := "v5.4.3"

fmt:
	clang-format -i ./*.c ./*.h -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"
	clang-format -i ./test/main/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120, SortIncludes: false}"

prepare:
	rm -rf test/build test/esp-idf test/tools
	curl -L -o test/esp-idf.zip https://github.com/espressif/esp-idf/releases/download/$(ESP_IDF_VERSION)/esp-idf-$(ESP_IDF_VERSION).zip
	unzip -q test/esp-idf.zip -d test
	mv test/esp-idf-$(ESP_IDF_VERSION) test/esp-idf
	rm test/esp-idf.zip

install:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; cd test/esp-idf; ./install.sh $(TARGET)

config:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py menuconfig

reconfigure:
	export IDF_TOOLS_PATH=$(shell pwd)/test/tools; . test/esp-idf/export.sh; cd test; idf.py set-target $(TARGET)
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
