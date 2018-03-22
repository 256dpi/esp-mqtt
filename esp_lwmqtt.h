#ifndef ESP_LWMQTT_H
#define ESP_LWMQTT_H

#include <lwmqtt.h>

/**
 * The lwmqtt timer object for the esp platform.
 */
typedef struct {
  uint32_t deadline;
} esp_lwmqtt_timer_t;

/**
 * The lwmqtt timer set callback for the esp platform.
 */
void esp_lwmqtt_timer_set(void *ref, uint32_t timeout);

/**
 * The lwmqtt timer get callback for the esp platform.
 */
int32_t esp_lwmqtt_timer_get(void *ref);

/**
 * The lwmqtt network object for the esp platform.
 */
typedef struct {
  int socket;
} esp_lwmqtt_network_t;

/**
 * Initiate a connection to the specified remote hose.
 */
lwmqtt_err_t esp_lwmqtt_network_connect(esp_lwmqtt_network_t *network, char *host, char *port);

/**
 * Terminate the connection.
 */
void esp_lwmqtt_network_disconnect(esp_lwmqtt_network_t *network);

/**
 * Will set available to the available amount of data in the underlying network buffer.
 */
lwmqtt_err_t esp_lwmqtt_network_peek(esp_lwmqtt_network_t *network, size_t *available);

/**
 * Will wait for a socket until data is available or the timeout has been reached.
 */
lwmqtt_err_t esp_lwmqtt_network_select(esp_lwmqtt_network_t *network, bool *available, uint32_t timeout);

/**
 * The lwmqtt network read callback for the esp platform.
 */
lwmqtt_err_t esp_lwmqtt_network_read(void *ref, uint8_t *buf, size_t len, size_t *read, uint32_t timeout);

/**
 * The lwmqtt network write callback for the esp platform.
 */
lwmqtt_err_t esp_lwmqtt_network_write(void *ref, uint8_t *buf, size_t len, size_t *sent, uint32_t timeout);

#endif  // ESP_LWMQTT_H
