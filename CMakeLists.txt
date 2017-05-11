cmake_minimum_required(VERSION 3.7)
project(esp-mqtt)

set(CMAKE_C_STANDARD 99)

include_directories(
        test/build/include
        xtensa-esp32-elf/xtensa-esp32-elf/include
        test/esp-idf/components/esp32/include
        test/esp-idf/components/freertos/include
        test/esp-idf/components/log/include
        test/esp-idf/components/nvs_flash/include
        test/esp-idf/components/tcpip_adapter/include
        test/esp-idf/components/lwip/include/lwip/port
        test/esp-idf/components/lwip/include/lwip
        lwmqtt/include
        .)

set(SOURCE_FILES
        esp-lwmqtt.c
        esp-lwmqtt.h
        mqtt.c
        mqtt.h
        test/main/main.c)

add_library(esp-mqtt ${SOURCE_FILES})
