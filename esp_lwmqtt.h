#ifndef ESP_LWMQTT_H
#define ESP_LWMQTT_H

#include <lwip/api.h>
#include <lwmqtt.h>

/**
 * The lwmqtt timer object for the esp platform.
 */
typedef struct { uint32_t deadline; } esp_lwmqtt_timer_t;

/**
 * The lwmqtt timer set callback for the esp platform.
 */
void esp_lwmqtt_timer_set(lwmqtt_client_t *client, void *ref, uint32_t timeout);

/**
 * The lwmqtt timer get callback for the esp platform.
 */
uint32_t esp_lwmqtt_timer_get(lwmqtt_client_t *client, void *ref);

/**
 * The lwmqtt network object for the esp platform.
 */
typedef struct {
  struct netconn *conn;
  struct netbuf *rest_buf;
  size_t rest_len;
} esp_lwmqtt_network_t;

/**
 * The initializer for the lwmqtt network object.
 */
#define esp_lwmqtt_default_network \
  { NULL, NULL, 0 }

/**
 * Initiate a connection to the specified remote hose.
 */
lwmqtt_err_t esp_lwmqtt_network_connect(esp_lwmqtt_network_t *network, char *host, int port);

/**
 * Terminate the connection.
 */
void esp_lwmqtt_network_disconnect(esp_lwmqtt_network_t *network);

/**
 * Will set available to the available amount of data in the underlying network buffer.
 */
lwmqtt_err_t esp_lwmqtt_network_peek(lwmqtt_client_t *client, esp_lwmqtt_network_t *network, size_t *available);

/**
 * The lwmqtt network read callback for the esp platform.
 */
lwmqtt_err_t esp_lwmqtt_network_read(lwmqtt_client_t *client, void *ref, uint8_t *buf, size_t len, size_t *read,
                                     uint32_t timeout);
/**
 * The lwmqtt network write callback for the esp platform.
 */
lwmqtt_err_t esp_lwmqtt_network_write(lwmqtt_client_t *client, void *ref, uint8_t *buf, size_t len, size_t *sent,
                                      uint32_t timeout);

#endif  // ESP_LWMQTT_H
