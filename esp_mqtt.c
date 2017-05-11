#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <lwmqtt.h>
#include <string.h>

#include "esp_lwmqtt.h"

#include "esp_mqtt.h"

#define ESP_MQTT_LOG_TAG "ESP-MQTT"

#define ESP_MQTT_LOCK(x) \
  do {                   \
  } while (xSemaphoreTake(x, portMAX_DELAY) != pdPASS)

#define ESP_MQTT_UNLOCK(x) xSemaphoreGive(x)

static SemaphoreHandle_t esp_mqtt_mutex;

static TaskHandle_t esp_mqtt_task;

#define ESP_MQTT_CONF_SIZE 32

static struct {
  char host[ESP_MQTT_CONF_SIZE];
  uint16_t port;
  char client_id[ESP_MQTT_CONF_SIZE];
  char username[ESP_MQTT_CONF_SIZE];
  char password[ESP_MQTT_CONF_SIZE];
} esp_mqtt_config;

static bool esp_mqtt_running = false;
static bool esp_mqtt_connected = false;

static esp_mqtt_status_callback_t esp_mqtt_status_callback = NULL;
static esp_mqtt_message_callback_t esp_mqtt_message_callback = NULL;

static lwmqtt_client_t esp_mqtt_client;

#define ESP_MQTT_COMMAND_TIMEOUT 2000

static esp_lwmqtt_network_t esp_mqtt_network = esp_lwmqtt_default_network;

static esp_lwmqtt_timer_t esp_mqtt_timer1, esp_mqtt_timer2;

#define ESP_MQTT_BUFFER_SIZE 256

static unsigned char esp_mqtt_send_buffer[ESP_MQTT_BUFFER_SIZE];
static unsigned char esp_mqtt_read_buffer[ESP_MQTT_BUFFER_SIZE + 1];  // plus null termination

void esp_mqtt_init(esp_mqtt_status_callback_t scb, esp_mqtt_message_callback_t mcb) {
  // set callbacks
  esp_mqtt_status_callback = scb;
  esp_mqtt_message_callback = mcb;

  // create mutex
  esp_mqtt_mutex = xSemaphoreCreateMutex();
}

static void esp_mqtt_message_handler(lwmqtt_client_t *c, void *ref, lwmqtt_string_t *topic, lwmqtt_message_t *msg) {
  // copy and null terminate topic
  char prefixed_topic[topic->len + 1];
  memcpy(prefixed_topic, topic->data, (size_t)topic->len);
  prefixed_topic[topic->len] = 0;

  // null terminate payload
  char *payload = msg->payload;
  payload[msg->payload_len] = 0;

  // call message callback without the locks to overcome any race condition
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);
  esp_mqtt_message_callback(topic->data, payload, (unsigned int)msg->payload_len);
  ESP_MQTT_LOCK(esp_mqtt_mutex);
}

static bool esp_mqtt_process_connect() {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // initialize the client
  lwmqtt_init(&esp_mqtt_client, esp_mqtt_send_buffer, ESP_MQTT_BUFFER_SIZE, esp_mqtt_read_buffer, ESP_MQTT_BUFFER_SIZE);

  lwmqtt_set_network(&esp_mqtt_client, &esp_mqtt_network, esp_lwmqtt_network_read, esp_lwmqtt_network_write);
  lwmqtt_set_timers(&esp_mqtt_client, &esp_mqtt_timer1, &esp_mqtt_timer2, esp_lwmqtt_timer_set, esp_lwmqtt_timer_get);
  lwmqtt_set_callback(&esp_mqtt_client, NULL, esp_mqtt_message_handler);

  // attempt network connection
  lwmqtt_err_t err = esp_lwmqtt_network_connect(&esp_mqtt_network, esp_mqtt_config.host, esp_mqtt_config.port);
  if (err != LWMQTT_SUCCESS) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "esp_lwmqtt_network_connect: %d", err);
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // setup connect data
  lwmqtt_options_t options = lwmqtt_default_options;
  options.keep_alive = 10;
  options.client_id = lwmqtt_str(esp_mqtt_config.client_id);
  options.username = lwmqtt_str(esp_mqtt_config.username);
  options.password = lwmqtt_str(esp_mqtt_config.password);

  // attempt connection
  lwmqtt_return_code_t return_code;
  err = lwmqtt_connect(&esp_mqtt_client, &options, NULL, &return_code, ESP_MQTT_COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_connect: %d", err);
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  return true;
}

static void esp_mqtt_process(void *p) {
  // connection loop
  for (;;) {
    // log attempt
    ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_process: begin connection attempt");

    // make connection attempt
    if (esp_mqtt_process_connect()) {
      // log success
      ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_process: attempt successful");

      // exit loop
      break;
    }

    // log fail
    ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_process: attempt failed");

    // delay loop by 1s and yield to other processes
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }

  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // set local flag
  esp_mqtt_connected = true;

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  // call callback if existing
  if (esp_mqtt_status_callback) {
    esp_mqtt_status_callback(ESP_MQTT_STATUS_CONNECTED);
  }

  // yield loop
  for (;;) {
    // acquire mutex
    ESP_MQTT_LOCK(esp_mqtt_mutex);

    // get the available bytes to be read
    int available = 0;
    lwmqtt_err_t err = esp_lwmqtt_network_peek(&esp_mqtt_client, &esp_mqtt_network, &available);
    if (err != LWMQTT_SUCCESS) {
      ESP_LOGE(ESP_MQTT_LOG_TAG, "esp_lwmqtt_network_peek: %d", err);
      break;
    }

    // yield to client if data is available
    if (available > 0) {
      err = lwmqtt_yield(&esp_mqtt_client, available, ESP_MQTT_COMMAND_TIMEOUT);
      if (err != LWMQTT_SUCCESS) {
        ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_yield: %d", err);
        break;
      }
    }

    // do mqtt background work
    err = lwmqtt_keep_alive(&esp_mqtt_client, ESP_MQTT_COMMAND_TIMEOUT);
    if (err != LWMQTT_SUCCESS) {
      ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_keep_alive: %d", err);
      break;
    }

    // release mutex
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);

    // yield to other processes
    vTaskDelay(1);
  }

  // mutex has already been acquired above

  // disconnect network
  esp_lwmqtt_network_disconnect(&esp_mqtt_network);

  // set local flags
  esp_mqtt_connected = false;
  esp_mqtt_running = false;

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_process: exit task");

  // call callback if existing
  if (esp_mqtt_status_callback) {
    esp_mqtt_status_callback(ESP_MQTT_STATUS_DISCONNECTED);
  }

  // delete task
  vTaskDelete(NULL);
}

void esp_mqtt_start(const char *host, unsigned int port, const char *client_id, const char *username,
                    const char *password) {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // check if already running
  if (esp_mqtt_running) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "esp_mqtt_start: already running");
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return;
  }

  // copy config
  strcpy(esp_mqtt_config.host, host);
  esp_mqtt_config.port = (uint16_t)port;
  strcpy(esp_mqtt_config.client_id, client_id);
  strcpy(esp_mqtt_config.username, username);
  strcpy(esp_mqtt_config.password, password);

  // create mqtt thread
  ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_start: create task");
  xTaskCreatePinnedToCore(esp_mqtt_process, "core-mqtt", 4096, NULL, 5, &esp_mqtt_task, 1);

  // set local flag
  esp_mqtt_running = true;

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);
}

bool esp_mqtt_subscribe(const char *topic, int qos) {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // check if still connected
  if (!esp_mqtt_connected) {
    ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_subscribe: not connected");
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // subscribe to topic
  lwmqtt_err_t err = lwmqtt_subscribe(&esp_mqtt_client, topic, (lwmqtt_qos_t)qos, ESP_MQTT_COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_subscribe: %d", err);
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  return true;
}

bool esp_mqtt_unsubscribe(const char *topic) {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // check if still connected
  if (!esp_mqtt_connected) {
    ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_unsubscribe: not connected");
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // unsubscribe from topic
  lwmqtt_err_t err = lwmqtt_unsubscribe(&esp_mqtt_client, topic, ESP_MQTT_COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_unsubscribe: %d", err);
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  return true;
}

bool esp_mqtt_publish(const char *topic, void *payload, uint16_t len, int qos, bool retained) {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // check if still connected
  if (!esp_mqtt_connected) {
    ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_publish: not connected");
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // prepare message
  lwmqtt_message_t message;
  message.qos = (lwmqtt_qos_t)qos;
  message.retained = retained;
  message.payload = payload;
  message.payload_len = len;

  // publish message
  lwmqtt_err_t err = lwmqtt_publish(&esp_mqtt_client, topic, &message, ESP_MQTT_COMMAND_TIMEOUT);
  if (err != LWMQTT_SUCCESS) {
    ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_publish: %d", err);
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return false;
  }

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);

  return true;
}

bool esp_mqtt_publish_str(const char *topic, const char *payload, int qos, bool retained) {
  return esp_mqtt_publish(topic, (char *)payload, (uint16_t)strlen(payload), qos, retained);
}

void esp_mqtt_stop() {
  // acquire mutex
  ESP_MQTT_LOCK(esp_mqtt_mutex);

  // return immediately if not running anymore
  if (!esp_mqtt_running) {
    ESP_MQTT_UNLOCK(esp_mqtt_mutex);
    return;
  }

  // attempt to properly disconnect a connected client
  if (esp_mqtt_connected) {
    lwmqtt_err_t err = lwmqtt_disconnect(&esp_mqtt_client, ESP_MQTT_COMMAND_TIMEOUT);
    if (err != LWMQTT_SUCCESS) {
      ESP_LOGE(ESP_MQTT_LOG_TAG, "lwmqtt_disconnect: %d", err);
    }

    // set flag
    esp_mqtt_connected = false;
  }

  // disconnect network
  esp_lwmqtt_network_disconnect(&esp_mqtt_network);

  // kill mqtt task
  ESP_LOGI(ESP_MQTT_LOG_TAG, "esp_mqtt_stop: deleting task");
  vTaskDelete(esp_mqtt_task);

  // set flag
  esp_mqtt_running = false;

  // release mutex
  ESP_MQTT_UNLOCK(esp_mqtt_mutex);
}
