cmake_minimum_required(VERSION 3.7)
project(esp-mqtt)

set(CMAKE_C_STANDARD 99)

include_directories(
        test/build/include
        test/xtensa-esp32-elf/xtensa-esp32-elf/include
        test/esp-idf/components/esp32/include
        test/esp-idf/components/esp_common/include
        test/esp-idf/components/esp_event/include
        test/esp-idf/components/esp_netif/include
        test/esp-idf/components/esp_wifi/include
        test/esp-idf/components/freertos/include
        test/esp-idf/components/log/include
        test/esp-idf/components/lwip/port/esp32/include
        test/esp-idf/components/lwip/lwip/src/include
        test/esp-idf/components/nvs_flash/include
        test/esp-idf/components/mbedtls/mbedtls/include
        test/esp-idf/components/mbedtls/port/include
        lwmqtt/include
        .)

set(SOURCE_FILES
        esp_lwmqtt.c
        esp_lwmqtt.h
        esp_mqtt.c
        esp_mqtt.h
        esp_tls_lwmqtt.c
        esp_tls_lwmqtt.h
        test/main/main.c)

add_library(esp-mqtt ${SOURCE_FILES})
