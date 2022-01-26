set(srcs
    "esp_lwmqtt.c"
    "esp_mqtt.c"
    "esp_tls_lwmqtt.c"
    "lwmqtt/src/client.c"
    "lwmqtt/src/helpers.c"
    "lwmqtt/src/packet.c"
    "lwmqtt/src/string.c")

idf_component_register(SRCS ${srcs}
    INCLUDE_DIRS "." "lwmqtt/include"
    REQUIRES mbedtls
)
