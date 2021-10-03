#ifndef ESP_MQTT_H
#define ESP_MQTT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The statuses emitted by the status callback.
 */
typedef enum esp_mqtt_status_t { ESP_MQTT_STATUS_DISCONNECTED, ESP_MQTT_STATUS_CONNECTED } esp_mqtt_status_t;

/**
 * The status callback.
 */
typedef void (*esp_mqtt_status_callback_t)(esp_mqtt_status_t);

/**
 * The message callback.
 */
typedef void (*esp_mqtt_message_callback_t)(const char *topic, uint8_t *payload, size_t len);

/**
 * Initialize the MQTT management system.
 *
 * Note: Should only be called once on boot.
 *
 * @param scb - The status callback.
 * @param mcb - The message callback.
 * @param buffer_size - The read and write buffer size.
 * @param command_timeout - The command timeout.
 */
void esp_mqtt_init(esp_mqtt_status_callback_t scb, esp_mqtt_message_callback_t mcb, size_t buffer_size,
                   int command_timeout);

#if defined(CONFIG_ESP_MQTT_TLS_ENABLE)
/**
 * Configure TLS connection.
 *
 * The specified CA certificate is not copied and must be available during the whole duration of the MQTT usage.
 *
 * Note: This method must be called before `esp_mqtt_start`.
 *
 * @param enable - Whether TLS should be used.
 * @param verify - Whether the connection should be verified.
 * @param ca_buf - The beginning of the CA certificate buffer.
 * @param ca_len - The length of the CA certificate buffer.
 * @return Whether TLS configuration was successful.
 */
bool esp_mqtt_tls(bool enable, bool verify, const uint8_t *ca_buf, size_t ca_len);
#endif

/**
 * Configure Last Will and Testament.
 *
 * Note: Must be called before `esp_mqtt_start`.
 *
 * @param topic - The LWT topic.
 * @param payload - The LWT payload.
 * @param qos - The LWT QoS level.
 * @param retained - The LWT retained flag.
 */
void esp_mqtt_lwt(const char *topic, const char *payload, int qos, bool retained);

/**
 * Start the MQTT process.
 *
 * The background process will attempt to connect to the specified broker once a second until a connection can be
 * established. This process can be interrupted by calling `esp_mqtt_stop();`. If a connection has been established,
 * the status callback will be called with `ESP_MQTT_STATUS_CONNECTED`. From that moment on the functions
 * `esp_mqtt_subscribe`, `esp_mqtt_unsubscribe` and `esp_mqtt_publish` can be used to interact with the broker.
 *
 * @param host - The broker host.
 * @param port - The broker port.
 * @param client_id - The client id.
 * @param username - The client username.
 * @param password - The client password.
 * @return Whether the operation was successful.
 */
bool esp_mqtt_start(const char *host, const char *port, const char *client_id, const char *username,
                    const char *password);

/**
 * Subscribe to specified topic.
 *
 * When false is returned the current operation failed and any subsequent interactions will also fail. This can be used
 * to handle errors early. As soon as the background process unblocks the error will be detected, the connection closed
 * and the status callback invoked with `ESP_MQTT_STATUS_DISCONNECTED`. That callback then can simply call
 * `esp_mqtt_start()` to attempt an reconnection.
 *
 * @param topic - The topic.
 * @param qos - The qos level.
 * @return Whether the operation was successful.
 */
bool esp_mqtt_subscribe(const char *topic, int qos);

/**
 * Unsubscribe from specified topic.
 *
 * When false is returned the current operation failed and any subsequent interactions will also fail. This can be used
 * to handle errors early. As soon as the background process unblocks the error will be detected, the connection closed
 * and the status callback invoked with `ESP_MQTT_STATUS_DISCONNECTED`. That callback then can simply call
 * `esp_mqtt_start()` to attempt an reconnection.
 *
 * @param topic - The topic.
 * @return Whether the operation was successful.
 */
bool esp_mqtt_unsubscribe(const char *topic);

/**
 * Publish bytes payload to specified topic.
 *
 * When false is returned the current operation failed and any subsequent interactions will also fail. This can be used
 * to handle errors early. As soon as the background process unblocks the error will be detected, the connection closed
 * and the status callback invoked with `ESP_MQTT_STATUS_DISCONNECTED`. That callback then can simply call
 * `esp_mqtt_start()` to attempt an reconnection.
 *
 * @param topic - The topic.
 * @param payload - The payload.
 * @param len - The payload length.
 * @param qos - The qos level.
 * @param retained - The retained flag.
 * @return Whether the operation was successful.
 */
bool esp_mqtt_publish(const char *topic, uint8_t *payload, size_t len, int qos, bool retained);

/**
 * Stop the MQTT process.
 *
 * Will stop initial connection attempts or disconnect any active connection.
 */
void esp_mqtt_stop();

#ifdef __cplusplus
}
#endif

#endif  // ESP_MQTT_H
