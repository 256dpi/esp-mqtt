#include <lwip/netdb.h>
#include <string.h>  // needed

// mbed TLS documentation: https://tls.mbed.org

#include "esp_tls_lwmqtt.h"

static void esp_tls_log(const char *name, int ret) {
  char str[256];
  mbedtls_strerror(ret, str, 256);
  ESP_LOGE("esp-mqtt", "%s: %s (%d)", name, str, ret);
}

lwmqtt_err_t esp_tls_lwmqtt_network_connect(esp_tls_lwmqtt_network_t *n, char *host, char *port) {
  // disconnect if not already the case
  esp_tls_lwmqtt_network_disconnect(n);

  // initialize support structures
  mbedtls_net_init(&n->socket);
  mbedtls_ssl_init(&n->ssl);
  mbedtls_ssl_config_init(&n->conf);
  mbedtls_x509_crt_init(&n->cacert);
  mbedtls_ctr_drbg_init(&n->ctr_drbg);
  mbedtls_entropy_init(&n->entropy);

  // setup entropy source
  int ret = mbedtls_ctr_drbg_seed(&n->ctr_drbg, mbedtls_entropy_func, &n->entropy, NULL, 0);
  if (ret != 0) {
    esp_tls_log("mbedtls_ctr_drbg_seed", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // parse ca certificate
  if (n->ca_buf) {
    ret = mbedtls_x509_crt_parse(&n->cacert, n->ca_buf, n->ca_len);
    if (ret != 0) {
      esp_tls_log("mbedtls_x509_crt_parse", ret);
      return LWMQTT_NETWORK_FAILED_CONNECT;
    }
  }

  // connect socket
  ret = mbedtls_net_connect(&n->socket, host, port, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    esp_tls_log("mbedtls_net_connect", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // load defaults
  ret = mbedtls_ssl_config_defaults(&n->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_config_defaults", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set ca certificate
  if (n->ca_buf) {
    mbedtls_ssl_conf_ca_chain(&n->conf, &n->cacert, NULL);
  }

  // set auth mode
  mbedtls_ssl_conf_authmode(&n->conf, (n->verify) ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);

  // set rng callback
  mbedtls_ssl_conf_rng(&n->conf, mbedtls_ctr_drbg_random, &n->ctr_drbg);

  // setup ssl context
  ret = mbedtls_ssl_setup(&n->ssl, &n->conf);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_setup", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set hostname
  ret = mbedtls_ssl_set_hostname(&n->ssl, host);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_set_hostname", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set bio callbacks
  mbedtls_ssl_set_bio(&n->ssl, &n->socket, mbedtls_net_send, mbedtls_net_recv, NULL);

  // verify certificate if requested
  if (n->verify) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&n->ssl);
    if (flags != 0) {
      char verify_buf[100] = {0};
      mbedtls_x509_crt_verify_info(verify_buf, sizeof(verify_buf), "  ! ", flags);
      ESP_LOGE("esp-mqtt", "%mbedtls_ssl_get_verify_result: %s (%d)", verify_buf, flags);
    }
  }

  // perform handshake
  ret = mbedtls_ssl_handshake(&n->ssl);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_handshake", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_wait(esp_tls_lwmqtt_network_t *n, bool *connected, uint32_t timeout) {
  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(n->socket.fd, &set);
  FD_SET(n->socket.fd, &ex_set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(n->socket.fd + 1, NULL, &set, &ex_set, &t);
  if (result < 0 || FD_ISSET(n->socket.fd, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set whether socket is connected
  *connected = result > 0;

  // set socket to blocking
  int ret = mbedtls_net_set_block(&n->socket);
  if (ret < 0) {
    esp_tls_log("mbedtls_net_set_block", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

void esp_tls_lwmqtt_network_disconnect(esp_tls_lwmqtt_network_t *n) {
  // check if network is available
  if (!n) {
    return;
  }

  // cleanup resources
  mbedtls_ssl_close_notify(&n->ssl);
  mbedtls_x509_crt_free(&n->cacert);
  mbedtls_entropy_free(&n->entropy);
  mbedtls_ssl_config_free(&n->conf);
  mbedtls_ctr_drbg_free(&n->ctr_drbg);
  mbedtls_ssl_free(&n->ssl);
  mbedtls_net_free(&n->socket);
}

lwmqtt_err_t esp_tls_lwmqtt_network_select(esp_tls_lwmqtt_network_t *n, bool *available, uint32_t timeout) {
  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(n->socket.fd, &set);
  FD_SET(n->socket.fd, &ex_set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(n->socket.fd + 1, &set, NULL, &ex_set, &t);
  if (result < 0 || FD_ISSET(n->socket.fd, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = result > 0;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_peek(esp_tls_lwmqtt_network_t *n, size_t *available, uint32_t timeout) {
  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set socket to non blocking
  int ret = mbedtls_net_set_nonblock(&n->socket);
  if (ret != 0) {
    esp_tls_log("mbedtls_net_set_nonblock", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // TODO: Directly peek on underlying socket?

  // check if socket is valid
  ret = mbedtls_ssl_read(&n->ssl, NULL, 0);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    esp_tls_log("mbedtls_ssl_read", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set available bytes
  *available = mbedtls_ssl_get_bytes_avail(&n->ssl);

  // set socket back to blocking
  ret = mbedtls_net_set_block(&n->socket);
  if (ret != 0) {
    esp_tls_log("mbedtls_net_set_block", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_read(void *ref, uint8_t *buffer, size_t len, size_t *received, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *n = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int ret = mbedtls_ssl_read(&n->ssl, buffer, len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret <= 0) {
    esp_tls_log("mbedtls_ssl_read", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // increment counter
  *received += ret;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_write(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *n = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int ret = mbedtls_ssl_write(&n->ssl, buffer, len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret < 0) {
    esp_tls_log("mbedtls_ssl_write", ret);
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // increment counter
  *sent += ret;

  return LWMQTT_SUCCESS;
}
