#include <stdlib.h>

#include <esp_event_loop.h>
#include <esp_log.h>
#include <esp_mqtt.h>
#include <esp_wifi.h>
#include <nvs_flash.h>

#define WIFI_SSID ""
#define WIFI_PASS ""

#define MQTT_HOST "public.cloud.shiftr.io"
#define MQTT_USER "public"
#define MQTT_PASS "public"

#define MQTT_PORT "1883"
#define MQTTS_PORT "8883"

#define PUBLISH_INTERVAL 1000
#define RESTART_INTERVAL 20000

// openssl s_client -showcerts -connect garage.cloud.shiftr.io:8883 -servername garage.cloud.shiftr.io
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
    // publish every second
    esp_mqtt_publish("/hello", (uint8_t *)"world", 5, 2, false);
    vTaskDelay(PUBLISH_INTERVAL / portTICK_PERIOD_MS);
  }
}

static void restart(void *_) {
  // initial start
  connect();

  for (;;) {
    // restart periodically
    vTaskDelay(RESTART_INTERVAL / portTICK_PERIOD_MS);
    esp_mqtt_stop();
    connect();
  }
}

static esp_err_t event_handler(void *ctx, system_event_t *event) {
  switch (event->event_id) {
    case SYSTEM_EVENT_STA_START:
      // connect to ap
      ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_connect());

      break;

    case SYSTEM_EVENT_STA_GOT_IP:
      break;

    case SYSTEM_EVENT_STA_DISCONNECTED:
      // reconnect Wi-Fi
      ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_connect());

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
    default:
      break;
  }
}

static void message_callback(const char *topic, uint8_t *payload, size_t len) {
  ESP_LOGI("test", "incoming: %s => %s (%d)", topic, payload, (int)len);
}

void app_main() {
  // initialize NVS flash
  ESP_ERROR_CHECK(nvs_flash_init());

  // initialize TCP/IP adapter
  tcpip_adapter_init();

  // register event handler
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));

  // initialize Wi-Fi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // set Wi-Fi storage to ram
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  // set wifi mode
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  // prepare Wi-Fi config
  wifi_config_t wifi_config = {.sta = {.ssid = WIFI_SSID, .password = WIFI_PASS}};
  ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

  // start Wi-Fi
  ESP_ERROR_CHECK(esp_wifi_start());

  // initialize mqtt
  esp_mqtt_init(status_callback, message_callback, 256, 2000);

  // create tasks
  xTaskCreatePinnedToCore(process, "process", 2048, NULL, 10, NULL, 1);
  xTaskCreatePinnedToCore(restart, "restart", 2048, NULL, 10, NULL, 1);
}
