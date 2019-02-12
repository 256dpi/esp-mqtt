# esp-mqtt

[![Build Status](https://travis-ci.org/256dpi/esp-mqtt.svg?branch=master)](https://travis-ci.org/256dpi/esp-mqtt)
[![Release](https://img.shields.io/github/release/256dpi/esp-mqtt.svg)](https://github.com/256dpi/esp-mqtt/releases)

**MQTT component for esp-idf projects based on the [lwmqtt](https://github.com/256dpi/lwmqtt) library**

This component bundles the lwmqtt client and adds a simple async API similar to other esp networking components. Secure connections are supported via the `mbedTLS` library.

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

Enable secure connection using TLS:

```c++
bool esp_mqtt_tls(bool enabled, bool verify, const uint8_t * ca_buf, size_t ca_len);
```

Optionally, configure a Last Will and Testament:

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
