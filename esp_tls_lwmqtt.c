#include <lwip/netdb.h>
#include <string.h>  // needed

// mbed TLS documentation: https://tls.mbed.org

#include "esp_tls_lwmqtt.h"

static void esp_tls_log(const char *name, int ret) {
  char str[256];
  mbedtls_strerror(ret, str, 256);
  ESP_LOGE("esp-mqtt", "%s: %s (%d)", name, str, ret);
}

lwmqtt_err_t esp_tls_lwmqtt_network_connect(esp_tls_lwmqtt_network_t *network, char *host, char *port) {
  // disconnect if not already the case
  esp_tls_lwmqtt_network_disconnect(network);

  // initialize support structures
  mbedtls_net_init(&network->socket);
  mbedtls_ssl_init(&network->ssl);
  mbedtls_ssl_config_init(&network->conf);
  mbedtls_x509_crt_init(&network->cacert);
  mbedtls_ctr_drbg_init(&network->ctr_drbg);
  mbedtls_entropy_init(&network->entropy);

  // setup entropy source
  int ret = mbedtls_ctr_drbg_seed(&network->ctr_drbg, mbedtls_entropy_func, &network->entropy, NULL, 0);
  if (ret != 0) {
    esp_tls_log("mbedtls_ctr_drbg_seed", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // parse ca certificate
  if (network->ca_buf) {
    ret = mbedtls_x509_crt_parse(&network->cacert, network->ca_buf, network->ca_len);
    if (ret != 0) {
      esp_tls_log("mbedtls_x509_crt_parse", ret);
      return LWMQTT_NETWORK_FAILED_CONNECT;
    }
  }

  // connect socket
  ret = mbedtls_net_connect(&network->socket, host, port, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    esp_tls_log("mbedtls_net_connect", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // load defaults
  ret = mbedtls_ssl_config_defaults(&network->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_config_defaults", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set ca certificate
  if (network->ca_buf) {
    mbedtls_ssl_conf_ca_chain(&network->conf, &network->cacert, NULL);
  }

  // set auth mode
  mbedtls_ssl_conf_authmode(&network->conf, (network->verify) ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);

  // set rng callback
  mbedtls_ssl_conf_rng(&network->conf, mbedtls_ctr_drbg_random, &network->ctr_drbg);

  // setup ssl context
  ret = mbedtls_ssl_setup(&network->ssl, &network->conf);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_setup",  ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set hostname
  ret = mbedtls_ssl_set_hostname(&network->ssl, host);
  if (ret != 0) {
    esp_tls_log("mbedtls_ssl_set_hostname", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set bio callbacks
  mbedtls_ssl_set_bio(&network->ssl, &network->socket, mbedtls_net_send, mbedtls_net_recv, NULL);

  // verify certificate if requested
  if (network->verify) {
    uint32_t flags = mbedtls_ssl_get_verify_result(&network->ssl);
    if (flags != 0) {
      char verify_buf[100] = {0};
      mbedtls_x509_crt_verify_info(verify_buf, sizeof(verify_buf), "  ! ", flags);
      ESP_LOGE("mbedtls_ssl_get_verify_result", "%s flag: 0x%x\n\n", verify_buf, flags);
    }
  }

  // perform handshake
  ret = mbedtls_ssl_handshake(&network->ssl);
  if (ret != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      esp_tls_log("mbedtls_ssl_handshake", ret);
    }

    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_wait(esp_tls_lwmqtt_network_t *network, bool *connected, uint32_t timeout) {
  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(network->socket.fd, &set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(network->socket.fd + 1, NULL, &set, &ex_set, &t);
  if (result < 0 || FD_ISSET(network->socket.fd, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set whether socket is connected
  *connected = result > 0;

  // set socket to blocking
  int ret = mbedtls_net_set_block(&network->socket);
  if (ret < 0) {
    esp_tls_log("mbedtls_net_set_block", ret);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  return LWMQTT_SUCCESS;
}

void esp_tls_lwmqtt_network_disconnect(esp_tls_lwmqtt_network_t *network) {
  // check if network is available
  if (!network) {
    return;
  }

  // cleanup resources
  mbedtls_ssl_close_notify(&network->ssl);
  mbedtls_x509_crt_free(&network->cacert);
  mbedtls_entropy_free(&network->entropy);
  mbedtls_ssl_config_free(&network->conf);
  mbedtls_ctr_drbg_free(&network->ctr_drbg);
  mbedtls_ssl_free(&network->ssl);
  mbedtls_net_free(&network->socket);
}

lwmqtt_err_t esp_tls_lwmqtt_network_select(esp_tls_lwmqtt_network_t *network, bool *available, uint32_t timeout) {
  // prepare sets
  fd_set set;
  fd_set ex_set;
  FD_ZERO(&set);
  FD_ZERO(&ex_set);
  FD_SET(network->socket.fd, &set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(network->socket.fd + 1, &set, NULL, &ex_set, &t);
  if (result < 0 || FD_ISSET(network->socket.fd, &ex_set)) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = result > 0;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_peek(esp_tls_lwmqtt_network_t *network, size_t *available, uint32_t timeout) {
  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(network->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set socket to non blocking
  int ret = mbedtls_net_set_nonblock(&network->socket);
  if (ret != 0) {
    esp_tls_log("mbedtls_net_set_nonblock", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // check if socket is valid
  ret = mbedtls_ssl_read(&network->ssl, NULL, 0);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    esp_tls_log("mbedtls_ssl_read", ret);
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set available bytes
  *available = mbedtls_ssl_get_bytes_avail(&network->ssl);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_read(void *ref, uint8_t *buffer, size_t len, size_t *received, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *network = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(network->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int ret = mbedtls_ssl_read(&network->ssl, buffer, len);
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
  esp_tls_lwmqtt_network_t *network = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(network->socket.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int ret = mbedtls_ssl_write(&network->ssl, buffer, len);
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
