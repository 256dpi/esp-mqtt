#include <lwip/netdb.h>
#include <string.h>  // needed

// Some docs about lwip:
// http://www.ecoscentric.com/ecospro/doc/html/ref/lwip-api-sequential-reference.html.
// http://ww1.microchip.com/downloads/en/AppNotes/Atmel-42233-Using-the-lwIP-Network-Stack_AP-Note_AT04055.pdf

#include <sdkconfig.h>
#include "esp_tls_lwmqtt.h"

lwmqtt_err_t esp_tls_lwmqtt_network_connect(esp_tls_lwmqtt_network_t *network, char *host, char *port) {
  // disconnect if not already the case
  esp_tls_lwmqtt_network_disconnect(network);

  // initialization mbedtls structures
  mbedtls_x509_crt_init(&network->cacert);
  mbedtls_ssl_init(&network->ssl);
  mbedtls_ssl_config_init(&network->conf);
  mbedtls_ctr_drbg_init(&network->ctr_drbg);
  mbedtls_entropy_init(&network->entropy);

  // setuping mbedtls connection
  if (mbedtls_ctr_drbg_seed(&network->ctr_drbg, mbedtls_entropy_func, &network->entropy, NULL, 0) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }
  // parse ca certificate
  if (mbedtls_x509_crt_parse(&network->cacert, network->cacert_buf, network->cacert_len) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  if (mbedtls_net_connect(&network->socket, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  if (mbedtls_ssl_config_defaults(&network->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                  MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  mbedtls_ssl_conf_ca_chain(&network->conf, &network->cacert, NULL);
  mbedtls_ssl_conf_authmode(&network->conf, (network->verify) ? MBEDTLS_SSL_VERIFY_REQUIRED : MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_rng(&network->conf, mbedtls_ctr_drbg_random, &network->ctr_drbg);

#if defined(CONFIG_MBEDTLS_DEBUG)
  mbedtls_esp_enable_debug_log(&network->conf, 4);
  ESP_LOGI("CONFIG_MBEDTLS_DEBUG", "DONE");
#endif

  if (mbedtls_ssl_setup(&network->ssl, &network->conf) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  if (mbedtls_ssl_set_hostname(&network->ssl, host) != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  mbedtls_ssl_set_bio(&network->ssl, &network->socket, mbedtls_net_send, mbedtls_net_recv, NULL);

  int flags;
  if (network->verify && (flags = mbedtls_ssl_get_verify_result(&network->ssl)) != 0) {
    char vrfy_buf[100];
    mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    ESP_LOGE("mbedtls_ssl_get_verify_result", "%s flag: 0x%x\n\n", vrfy_buf, flags);
  }

  int ret;
  if ((ret = mbedtls_ssl_handshake(&network->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      ESP_LOGE("mbedtls_ssl_handshake", "ERORR: -0x%x", -ret);
    }
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }
  network->enable = true;
  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_wait(esp_tls_lwmqtt_network_t *network, bool *connected, uint32_t timeout) {
  // prepare set
  fd_set set;
  FD_ZERO(&set);
  FD_SET(network->socket.fd, &set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = lwip_select(network->socket.fd + 1, NULL, &set, NULL, &t);
  if (result < 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // set whether socket is connected
  *connected = result > 0;

  // set socket to blocking
  int ret = mbedtls_net_set_block(&network->socket);
  if (ret < 0) {
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

  network->enable = false;
}

lwmqtt_err_t esp_tls_lwmqtt_network_select(esp_tls_lwmqtt_network_t *network, bool *available, uint32_t timeout) {
  // prepare set
  fd_set set;
  FD_ZERO(&set);
  FD_SET(network->socket.fd, &set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(network->socket.fd + 1, &set, NULL, NULL, &t);
  if (result < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = result > 0;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_peek(esp_tls_lwmqtt_network_t *network, size_t *available, uint32_t timeout) {
  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = lwip_setsockopt_r(network->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set socket to non blocking
  int ret = mbedtls_net_set_nonblock(&network->socket);
  if (ret != 0) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // get the available bytes on the socket
  ret = mbedtls_ssl_read(&network->ssl, NULL, 0);
  if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  *available = mbedtls_ssl_get_bytes_avail(&network->ssl);

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_read(void *ref, uint8_t *buffer, size_t len, size_t *read, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *network = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = lwip_setsockopt_r(network->socket.fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int ret = mbedtls_ssl_read(&network->ssl, buffer, len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret <= 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // increment counter
  *read += ret;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_tls_lwmqtt_network_write(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout) {
  // cast network reference
  esp_tls_lwmqtt_network_t *network = (esp_tls_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = lwip_setsockopt_r(network->socket.fd, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int ret = mbedtls_ssl_write(&network->ssl, buffer, len);
  if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
    return LWMQTT_SUCCESS;
  } else if (ret < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // increment counter
  *sent += ret;

  return LWMQTT_SUCCESS;
}
