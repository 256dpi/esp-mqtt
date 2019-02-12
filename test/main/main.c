#include <stdlib.h>

#include <esp_event_loop.h>
#include <esp_log.h>
#include <esp_mqtt.h>
#include <esp_wifi.h>
#include <nvs_flash.h>

#define WIFI_SSID ""
#define WIFI_PASS ""

#define MQTT_HOST "broker.shiftr.io"
#define MQTT_USER "try"
#define MQTT_PASS "try"

#define MQTT_PORT "1883"
#define MQTTS_PORT "8883"

// openssl s_client -showcerts -connect broker.shiftr.io:8883
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[] asm("_binary_server_root_cert_pem_end");

static void connect() {
  static bool use_tls = false;

  // cycle use tls
  use_tls = !use_tls;

  // start mqtt
  ESP_LOGI("test", "starting mqtt with tls=%d", use_tls);
  esp_mqtt_tls(use_tls, true, server_root_cert_pem_start, server_root_cert_pem_end - server_root_cert_pem_start);
  esp_mqtt_start(MQTT_HOST, use_tls ? MQTTS_PORT : MQTT_PORT, "esp-mqtt", MQTT_USER, MQTT_PASS);
}

static void process(void *p) {
  for (;;) {
    // publish roughly every second
    esp_mqtt_publish("/hello", (uint8_t *)"world", 5, 2, false);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
}

static void restart(void *_) {
  for (;;) {
    // stop and start mqtt 15s
    vTaskDelay(15000 / portTICK_PERIOD_MS);
    esp_mqtt_stop();
    connect();
  }
}

static esp_err_t event_handler(void *ctx, system_event_t *event) {
  switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
      // connect to ap
      esp_wifi_connect();

      break;

    case SYSTEM_EVENT_STA_GOT_IP:
      // start mqtt
      connect();

      break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
      // stop mqtt
      esp_mqtt_stop();

      // reconnect wifi
      esp_wifi_connect();

      break;

    default:
      break;
  }

  return ESP_OK;
}

static void status_callback(esp_mqtt_status_t status) {
  switch (status) {
    case ESP_MQTT_STATUS_CONNECTED:
      // subscribe
      esp_mqtt_subscribe("/hello", 2);

      break;

    case ESP_MQTT_STATUS_DISCONNECTED:
      // reconnect
      connect();

      break;
  }
}

static void message_callback(const char *topic, uint8_t *payload, size_t len) {
  ESP_LOGI("test", "incoming: %s => %s (%d)", topic, payload, (int)len);
}

void app_main() {
  // initialize nvs flash
  ESP_ERROR_CHECK(nvs_flash_init());

  // initialize tcp/ip adapter
  tcpip_adapter_init();

  // register event handler
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

  // initialize wifi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // set wifi storage to ram
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  // set wifi mode
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  // prepare wifi config
  wifi_config_t wifi_config = {.sta = {.ssid = WIFI_SSID, .password = WIFI_PASS}};
  ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

  // start wifi
  ESP_ERROR_CHECK(esp_wifi_start());

  // initialize mqtt
  esp_mqtt_init(status_callback, message_callback, 256, 2000);

  // create tasks
  xTaskCreatePinnedToCore(process, "process", 2048, NULL, 10, NULL, 1);
  xTaskCreatePinnedToCore(restart, "restart", 2048, NULL, 10, NULL, 1);
}
