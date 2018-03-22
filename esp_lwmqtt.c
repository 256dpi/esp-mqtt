#include <lwip/netdb.h>

// Some docs about lwip:
// http://www.ecoscentric.com/ecospro/doc/html/ref/lwip-api-sequential-reference.html.
// http://ww1.microchip.com/downloads/en/AppNotes/Atmel-42233-Using-the-lwIP-Network-Stack_AP-Note_AT04055.pdf

#include "esp_lwmqtt.h"

void esp_lwmqtt_timer_set(void *ref, uint32_t timeout) {
  // cast timer reference
  esp_lwmqtt_timer_t *t = (esp_lwmqtt_timer_t *)ref;

  // set deadline
  t->deadline = (xTaskGetTickCount() * portTICK_PERIOD_MS) + timeout;
}

int32_t esp_lwmqtt_timer_get(void *ref) {
  // cast timer reference
  esp_lwmqtt_timer_t *t = (esp_lwmqtt_timer_t *)ref;

  return (int32_t)t->deadline - (int32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

lwmqtt_err_t esp_lwmqtt_network_connect(esp_lwmqtt_network_t *network, char *host, char *port) {
  // disconnect if not already the case
  esp_lwmqtt_network_disconnect(network);

  // prepare hints
  struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};

  // lookup ip address
  struct addrinfo *res;
  int r = getaddrinfo(host, port, &hints, &res);
  if (r != 0 || res == NULL) {
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // create socket
  network->socket = socket(res->ai_family, res->ai_socktype, 0);
  if (network->socket < 0) {
    freeaddrinfo(res);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // connect socket
  r = connect(network->socket, res->ai_addr, res->ai_addrlen);
  if (r < 0) {
    close(network->socket);
    freeaddrinfo(res);
    return LWMQTT_NETWORK_FAILED_CONNECT;
  }

  // free address
  freeaddrinfo(res);

  return LWMQTT_SUCCESS;
}

void esp_lwmqtt_network_disconnect(esp_lwmqtt_network_t *network) {
  // close socket if present
  if (network->socket) {
    close(network->socket);
    network->socket = 0;
  }
}

lwmqtt_err_t esp_lwmqtt_network_select(esp_lwmqtt_network_t *network, bool *available, uint32_t timeout) {
  // prepare set
  fd_set set;
  FD_ZERO(&set);
  FD_SET(network->socket, &set);

  // wait for data
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int result = select(network->socket + 1, &set, NULL, NULL, &t);
  if (result < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // set whether data is available
  *available = result > 0;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_lwmqtt_network_peek(esp_lwmqtt_network_t *network, size_t *available) {
  // get the available bytes on the socket
  int rc = ioctl(network->socket, FIONREAD, available);
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_lwmqtt_network_read(void *ref, uint8_t *buffer, size_t len, size_t *read, uint32_t timeout) {
  // cast network reference
  esp_lwmqtt_network_t *n = (esp_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // read from socket
  int bytes = recv(n->socket, buffer, len, 0);
  if (bytes < 0 && errno != EAGAIN) {
    return LWMQTT_NETWORK_FAILED_READ;
  }

  // increment counter
  *read += bytes;

  return LWMQTT_SUCCESS;
}

lwmqtt_err_t esp_lwmqtt_network_write(void *ref, uint8_t *buffer, size_t len, size_t *sent, uint32_t timeout) {
  // cast network reference
  esp_lwmqtt_network_t *n = (esp_lwmqtt_network_t *)ref;

  // set timeout
  struct timeval t = {.tv_sec = timeout / 1000, .tv_usec = (timeout % 1000) * 1000};
  int rc = setsockopt(n->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&t, sizeof(t));
  if (rc < 0) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // write to socket
  int bytes = (int)send(n->socket, buffer, len, 0);
  if (bytes < 0 && errno != EAGAIN) {
    return LWMQTT_NETWORK_FAILED_WRITE;
  }

  // increment counter
  *sent += bytes;

  return LWMQTT_SUCCESS;
}
