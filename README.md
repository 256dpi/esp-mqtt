# esp-mqtt

[![Build Status](https://travis-ci.org/256dpi/esp-mqtt.svg?branch=master)](https://travis-ci.org/256dpi/esp-mqtt)
[![Release](https://img.shields.io/github/release/256dpi/esp-mqtt.svg)](https://github.com/256dpi/esp-mqtt/releases)

**MQTT component for esp-idf projects based on the [lwmqtt](https://github.com/256dpi/lwmqtt) library**

This component bundles the lwmqtt client and adds a simple async API similar to other esp networking components.

## Installation

You can install the component by adding it as a git submodule:

```bash
git submodule add https://github.com/256dpi/esp-mqtt.git components/esp-mqtt
git submodule update --init --recursive
```

The component will automatically enable the LWIP receive buffers.

### PlatformIO

You need to set `CONFIG_LWIP_SO_RCVBUF=y` manually in `sdkconfig`.

## Example

An example can be found here: https://github.com/256dpi/esp-mqtt/blob/master/test/main/main.c.

## Notes

If you are sending large messages, setting `CONFIG_USE_ONLY_LWIP_SELECT=y` might prevent [some issues](https://github.com/espressif/esp-mqtt/issues/48).

## API

Initialize the component once by passing the necessary callbacks:

```c++
void esp_mqtt_init(esp_mqtt_status_callback_t scb, esp_mqtt_message_callback_t mcb,
                   size_t buffer_size, int command_timeout);
```

Optionally, configure a Last Will and Testament (a topic to be published by the broker in the event of an ungraceful disconnection):

```c++
void esp_mqtt_lwt(const char *topic, const char *payload, int qos, bool retained);
```

When the WiFi connection has been established, start the process:

```c++
bool esp_mqtt_start(const char *host, const char *port, const char *client_id,
                    const char *username, const char *password);
```

When the client has connected, interact with the broker:

```c++
bool esp_mqtt_subscribe(const char *topic, int qos);
bool esp_mqtt_unsubscribe(const char *topic);
bool esp_mqtt_publish(const char *topic, uint8_t *payload, size_t len, int qos, bool retained);
```

If the WiFi connection has been lost, stop the process:

```c++
void esp_mqtt_stop();
```
#### TLS connection

**TLS connection option based on the [mbedtls](https://github.com/espressif/esp-idf/tree/master/components/mbedtls) component esp-idf framework.**

There are 3 mode of connections which you can set from component configuration menu in section
```Connection type```:
 + ```Secure mbedtls and unsecure connection enable``` - default mode which allows use both connection secure or unsecure.
 + ```Use no secure connection only``` - mode allow use only unsecure connection type. In this mode you can decrease
```MQTT background process task stack size``` to 4096. In this mode you get minimal memmory size of component in firmware.
+ ```Use secure mbedtls connection only``` - mode allow use only secure connection. 

To enable tls connection:
 + Choose ```Secure mbedtls and unsecure connection enable``` or ```Use secure mbedtls connection only``` in menu
 ```Connection type``` of esp-mqtt component config.
 + Change ```MQTT background process task stack size``` to ```9216``` minimum in esp-mqtt component config.
 + Get CA certificate from chain of certificates call ```openssl s_client -showcerts -connect broker.shiftr.io:8883```
 (change host and port of your secure mqtt broker server).
 + Put it in file ```server_root_cert.pem``` in main directory of your project. See example.
 + Add to your ```component.mk``` file of main directory of your project 
 ```c++
 COMPONENT_EMBED_TXTFILES := server_root_cert.pem
 ```
 + Call
 ```c++
 bool esp_mqtt_tls(bool verify, const unsigned char * cacert, size_t cacert_len)
 ```
 to set verify option and CA certificate in tls structure before calling
 ```c++
 void esp_mqtt_start(const char *host, const char *port, const char *client_id,
                     const char *username, const char *password);
 ```