#include <stdlib.h>

#include <esp_event.h>
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
  ESP_LOGI("test", "starting mqtt (tls=%d)", use_tls);
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

static void event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
  if (event_base == WIFI_EVENT) {
    switch (event_id) {
      case WIFI_EVENT_STA_START:
        // connect to ap
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_connect());

        break;

      case IP_EVENT_STA_GOT_IP:
        break;

      case WIFI_EVENT_STA_DISCONNECTED:
        // reconnect Wi-Fi
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_connect());

        break;

      default:
        break;
    }
  }
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

static void message_callback(const char *topic, const uint8_t *payload, size_t len, int qos, bool retained) {
  ESP_LOGI("test", "incoming: %s => %s (len=%d qos=%d ret=%d)", topic, payload, (int)len, qos, retained);
}

void app_main() {
  // initialize NVS flash
  ESP_ERROR_CHECK(nvs_flash_init());

  // initialize networking
  ESP_ERROR_CHECK(esp_netif_init());

  // create default event loop
  ESP_ERROR_CHECK(esp_event_loop_create_default());

  // enable Wi-Fi
  esp_netif_create_default_wifi_sta();

  // initialize Wi-Fi
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));

  // set Wi-Fi storage to ram
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  // set wifi mode
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  // register event handlers
  ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
  ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));

  // prepare Wi-Fi config
  wifi_config_t wifi_config = {.sta = {.ssid = WIFI_SSID, .password = WIFI_PASS}};
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

  // start Wi-Fi
  ESP_ERROR_CHECK(esp_wifi_start());

  // initialize mqtt
  esp_mqtt_init(status_callback, message_callback, 256, 2000, 1);

  // create tasks
  xTaskCreatePinnedToCore(process, "process", 4096, NULL, 10, NULL, 1);
  xTaskCreatePinnedToCore(restart, "restart", 4066, NULL, 10, NULL, 1);
}
