#ifndef ESP_MQTT_H
#define ESP_MQTT_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Default read and write buffer size to 256 bytes.
 */
#ifndef ESP_MQTT_BUFFER_SIZE
#define ESP_MQTT_BUFFER_SIZE 256
#endif

/**
 * Default command timeout to 2000ms.
 */
#ifndef ESP_MQTT_COMMAND_TIMEOUT
#define ESP_MQTT_COMMAND_TIMEOUT 2000
#endif

/**
 * The statuses emitted by the callback.
 */
typedef enum esp_mqtt_status_t { ESP_MQTT_STATUS_DISCONNECTED, ESP_MQTT_STATUS_CONNECTED } esp_mqtt_status_t;

/**
 * The status change callback.
 */
typedef void (*esp_mqtt_status_callback_t)(esp_mqtt_status_t);

/**
 * The message callback.
 */
typedef void (*esp_mqtt_message_callback_t)(const char *topic, const char *payload, unsigned int len);

/**
 * Initialize the MQTT management system.
 *
 * Note: Should only be called once on boot.
 */
void esp_mqtt_init(esp_mqtt_status_callback_t scb, esp_mqtt_message_callback_t mcb);

/**
 * Start the MQTT process.
 *
 * @param host
 * @param port
 * @param client_id
 * @param username
 * @param password
 * @param base_topic
 */
void esp_mqtt_start(const char *host, unsigned int port, const char *client_id, const char *username,
                    const char *password);

/**
 * Subscribe to specified topic.
 *
 * @param topic
 * @return
 */
bool esp_mqtt_subscribe(const char *topic, int qos);

/**
 * Unsubscribe from specified topic.
 *
 * @param topic
 * @return
 */
bool esp_mqtt_unsubscribe(const char *topic);

/**
 * Publish bytes payload to specified topic.
 *
 * @param topic
 * @param payload
 * @param len
 * @param qos
 * @param retained
 * @return
 */
bool esp_mqtt_publish(const char *topic, void *payload, uint16_t len, int qos, bool retained);

/**
 * Publish string to specified topic.
 *
 * @param topic
 * @param payload
 * @param qos
 * @param retained
 * @return
 */
bool esp_mqtt_publish_str(const char *topic, const char *payload, int qos, bool retained);

/**
 * Stop the MQTT process.
 */
void esp_mqtt_stop();

#endif  // ESP_MQTT_H
