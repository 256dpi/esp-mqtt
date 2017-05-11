#ifndef ESP_LWMQTT_H
#define ESP_LWMQTT_H

#include <lwip/api.h>
#include <lwmqtt.h>

/**
 * The lwmqtt timer object for the esp platform.
 */
typedef struct { unsigned long deadline; } esp_lwmqtt_timer_t;

/**
 * The lwmqtt timer set callback for the esp platform.
 *
 * @param client
 * @param ref
 */
void esp_lwmqtt_timer_set(lwmqtt_client_t *client, void *ref, unsigned int);

/**
 * The lwmqtt timer get callback for the esp platform.
 *
 * @param client
 * @param ref
 * @return
 */
unsigned int esp_lwmqtt_timer_get(lwmqtt_client_t *client, void *ref);

/**
 * The lwmqtt network object for the esp platform.
 */
typedef struct {
  struct netconn *conn;
  struct netbuf *rest_buf;
  int rest_len;
} esp_lwmqtt_network_t;

/**
 * The initializer for the lwmqtt network object.
 */
#define esp_lwmqtt_default_network \
  { NULL, NULL, 0 }

/**
 * Initiate a connection to the specified remote hose.
 *
 * @param network
 * @param host
 * @param port
 * @return
 */
lwmqtt_err_t esp_lwmqtt_network_connect(esp_lwmqtt_network_t *network, char *host, int port);

/**
 * Terminate the connection.
 *
 * @param network
 */
void esp_lwmqtt_network_disconnect(esp_lwmqtt_network_t *network);

/**
 * Will set available to the available amount of data in the underlying network buffer.
 *
 * @param client
 * @param network
 * @param available
 * @return
 */
lwmqtt_err_t esp_lwmqtt_network_peek(lwmqtt_client_t *client, esp_lwmqtt_network_t *network, int *available);

/**
 * The lwmqtt network read callback for the esp platform.
 *
 * @param client
 * @param ref
 * @param buf
 * @param len
 * @param read
 * @param timeout
 * @return
 */
lwmqtt_err_t esp_lwmqtt_network_read(lwmqtt_client_t *client, void *ref, unsigned char *buf, int len, int *read,
                                     unsigned int timeout);
/**
 * The lwmqtt network write callback for the esp platform.
 *
 * @param client
 * @param ref
 * @param buf
 * @param len
 * @param sent
 * @param timeout
 * @return
 */
lwmqtt_err_t esp_lwmqtt_network_write(lwmqtt_client_t *client, void *ref, unsigned char *buf, int len, int *sent,
                                      unsigned int timeout);

#endif  // ESP_LWMQTT_H
