#include <esp_tls.h>
#include <esp_log.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <esp_crt_bundle.h>

#include "esp_tls_lwmqtt.h"

#define TAG "esp-mqtt"

static void esp_tls_log(esp_tls_t *ctx, const char *name) {
  // get error handle
  esp_tls_error_handle_t error_handle;
  ESP_ERROR_CHECK(esp_tls_get_error_handle(ctx, &error_handle));

  // get last error
  int ret = 0;
  esp_err_t err = esp_tls_get_and_clear_last_error(error_handle, &ret, NULL);
  if (err < ESP_ERR_ESP_TLS_BASE) {
    ESP_ERROR_CHECK(err);
  }

  // format error
  char str[256] = {0};
  mbedtls_strerror(ret, str, sizeof(str));
  ESP_LOGE(TAG, "%s: err=%d ret=%d str='%s'", name, err, ret, str);
}

lwmqtt_err_t esp_tls_lwmqtt_network_connect(esp_tls_lwmqtt_network_t *n, char *host, char *port) {
  // disconnect if not already the case
  esp_tls_lwmqtt_network_disconnect(n);

  // parse port
  int port_num = atoi(port);
  if (port_num <= 0 || port_num > 65535) {
    ESP_LOGE(TAG, "esp_tls_lwmqtt_network_connect: port='%s'", port);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // build TLS configuration
  esp_tls_cfg_t cfg = {
      .timeout_ms = 10000,
      .cacert_buf = n->ca_buf,
      .cacert_bytes = n->ca_len,
      .skip_common_name = !n->verify,
#ifdef CONFIG_ESP_MQTT_TLS_CERTS
      .crt_bundle_attach = n->ca_buf == NULL ? esp_crt_bundle_attach : NULL,
#endif
  };

  // allocate TLS context
  n->tls = esp_tls_init();
  if (!n->tls) {
    ESP_LOGE(TAG, "esp_tls_init failed");
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // perform asynchronous connection
  int ret = esp_tls_conn_new_async(host, strlen(host), port_num, &cfg, n->tls);
  if (ret < 0) {
    ESP_LOGE(TAG, "esp_tls_conn_new_async: ret=%d", ret);
    esp_tls_lwmqtt_network_disconnect(n);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_wait(esp_tls_lwmqtt_network_t *n, bool *connected, uint32_t timeout) {
  // get socket
  int socket = 0;
  if (esp_tls_get_conn_sockfd(n->tls, &socket) != ESP_OK) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(socket, &set);
  FD_SET(socket, &ex_set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(socket + 1, NULL, &set, &ex_set, &t);
  if (result < 0 || FD_ISSET(socket, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set whether socket is connected
  *connected = (result > 0) && FD_ISSET(socket, &set);

  // set socket to blocking
  int ret = fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) & ~O_NONBLOCK);
  if (ret < 0) {
    ESP_LOGE(TAG, "fcntl: ret=%d", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

void esp_tls_lwmqtt_network_disconnect(esp_tls_lwmqtt_network_t *n) {
  // check if network is available
  if (!n || !n->tls) {
    return;
  }

  // destroy connection
  esp_tls_conn_destroy(n->tls);

  // clear state
  n->tls = NULL;
}

lwmqtt_err_t esp_tls_lwmqtt_network_select(esp_tls_lwmqtt_network_t *n, bool *available, uint32_t timeout) {
  // get socket
  int socket = 0;
  if (esp_tls_get_conn_sockfd(n->tls, &socket) != ESP_OK) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(socket, &set);
  FD_SET(socket, &ex_set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(socket + 1, &set, NULL, &ex_set, &t);
  if (result < 0 || FD_ISSET(socket, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = (result > 0) && FD_ISSET(socket, &set);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_peek(esp_tls_lwmqtt_network_t *n, size_t *available, uint32_t timeout) {
  // get socket
  int socket = 0;
  if (esp_tls_get_conn_sockfd(n->tls, &socket) != ESP_OK) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set socket to non blocking
  int ret = fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) | O_NONBLOCK);
  if (ret < 0) {
    ESP_LOGE(TAG, "fcntl: ret=%d", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // check if socket is valid
  ret = esp_tls_conn_read(n->tls, NULL, 0);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    esp_tls_log(n->tls, "esp_tls_conn_read");
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set available bytes
  ssize_t avail = esp_tls_get_bytes_avail(n->tls);
  if (avail > 0) {
    *available = avail;
  }

  // set socket back to blocking
  ret = fcntl(socket, F_SETFL, fcntl(socket, F_GETFL) & ~O_NONBLOCK);
  if (ret < 0) {
    ESP_LOGE(TAG, "fcntl: ret=%d", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_read(void *ref, uint8_t *buffer, size_t len, size_t *received, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *n = ref;

  // check state
  if (!n || !n->tls) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // get socket
  int socket = 0;
  if (esp_tls_get_conn_sockfd(n->tls, &socket) != ESP_OK) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int ret = esp_tls_conn_read(n->tls, buffer, len);
  if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret <= 0) {
    esp_tls_log(n->tls, "esp_tls_conn_read");
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // increment counter
  *received += ret;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_write(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *n = ref;

  // check state
  if (!n || !n->tls) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // get socket
  int socket = 0;
  if (esp_tls_get_conn_sockfd(n->tls, &socket) != ESP_OK) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int ret = esp_tls_conn_write(n->tls, buffer, len);
  if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret < 0) {
    esp_tls_log(n->tls, "esp_tls_conn_write");
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // increment counter
  *sent += ret;

  return LWMQTT_SUCCESS;
}
