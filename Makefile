fmt:
	clang-format -i ./*.c ./*.h -style="{BasedOnStyle: Google, ColumnLimit: 120}"
	clang-format -i ./test/main/*.c -style="{BasedOnStyle: Google, ColumnLimit: 120}"

monitor: test/xtensa-esp32-elf test/esp-idf
	@clear
	pyserial-miniterm /dev/cu.SLAB_USBtoUART 115200 --rts 0 --dtr 0 --raw --exit-char 99

# IDFv3

UNAME := $(shell uname)

XTENSA_TOOLCHAIN := "xtensa-esp32-elf-linux64-1.22.0-97-gc752ad5-5.2.0.tar.gz"
ifeq ($(UNAME), Darwin)
XTENSA_TOOLCHAIN := "xtensa-esp32-elf-macos-1.22.0-97-gc752ad5-5.2.0.tar.gz"
endif

ESP_IDF_VERSION := "v3.3.5"

test/xtensa-esp32-elf:
	wget https://dl.espressif.com/dl/$(XTENSA_TOOLCHAIN)
	cd test; tar -xzf ../$(XTENSA_TOOLCHAIN)
	rm *.tar.gz

test/esp-idf:
	git clone --recursive  https://github.com/espressif/esp-idf.git test/esp-idf
	cd test/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION)
	cd test/esp-idf/; git submodule update --recursive --init

update:
	cd test/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION)
	cd test/esp-idf/; git submodule update --recursive --init

defconfig: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make defconfig

menuconfig: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make menuconfig

erase: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make erase_flash

clean: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make clean

build: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make

flash: test/xtensa-esp32-elf test/esp-idf
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make flash

idf-monitor: test/xtensa-esp32-elf test/esp-idf test/components/esp-mqtt
	export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; cd ./test; make monitor

debug:
	 export PATH=$(shell pwd)/test/xtensa-esp32-elf/bin:$$PATH; export IDF_PATH=$(shell pwd)/test/esp-idf; ./test/esp-idf/components/espcoredump/espcoredump.py info_corefile -t b64 -c ./test/dump.txt ./test/build/esp-mqtt.elf

run: build flash monitor

# IDFv4

# Note: esptool v3.2 may have issues flashing, if so manually downgrade to v3.1

ESP_IDF_VERSION4 := "v4.3.2"

test4/esp-idf:
	git clone --recursive  https://github.com/espressif/esp-idf.git test4/esp-idf
	cd test4/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION4)
	cd test4/esp-idf/; git submodule update --recursive --init

update4:
	cd test4/esp-idf; git fetch; git checkout $(ESP_IDF_VERSION4)
	cd test4/esp-idf/; git submodule update --recursive --init

install4:
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; cd test4/esp-idf; ./install.sh

menuconfig4: test/esp-idf
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py menuconfig

erase4: test/esp-idf
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py erase_flash -p /dev/cu.SLAB_USBtoUART

clean4: test/esp-idf
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py clean

build4: test/esp-idf
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py build

flash4: test/esp-idf
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py flash -p /dev/cu.SLAB_USBtoUART -b 921600

idf-monitor4: test/esp-idf test/components/esp-mqtt
	export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; source ./test4/esp-idf/export.sh; cd ./test4; idf.py monitor -p /dev/cu.SLAB_USBtoUART

debug4:
	 export IDF_TOOLS_PATH=$(shell pwd)/test4/tools; export IDF_PATH=$(shell pwd)/test/esp-idf; ./test4/esp-idf/components/espcoredump/espcoredump.py info_corefile -t b64 -c ./test/dump.txt ./test/build/esp-mqtt.elf

run4: build4 flash4 monitor
