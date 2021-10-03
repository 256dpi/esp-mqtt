cmake_minimum_required(VERSION 3.7)
set(CMAKE_C_STANDARD 99)


FILE(GLOB_RECURSE sources
    "esp_lwmqtt.c"
    "esp_mqtt.c"
    "esp_tls_lwmqtt.c"
    "lwmqtt/src/*.*")

idf_component_register(SRCS ${sources}
    INCLUDE_DIRS "." "lwmqtt/include"
    REQUIRES mbedtls
)