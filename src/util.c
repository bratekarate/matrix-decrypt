#include "matrix_session_extract.h"

void print_bytes(const char *bytes, const size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%c", bytes[i]);
  }
}

void print_bytes_int(const char *bytes, const size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%d ", bytes[i]);
    // printf("%s0x%02x ", bytes[i]<0?"-":"", bytes[i]<0?-(unsigned)bytes[i]:bytes[i]);
  }
}

void print_hex_bytes(const char *bytes, const size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%02X", bytes[i]);
  }
}

void print_uint8(const u_int8_t *bytes, const size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%" PRIu8, bytes[i]);
  }
}

void print_session(ParsedSession *session) {
  printf("salt:\t\t\t");
  print_bytes_int(session->salt, sizeof(session->salt));
  printf("\n");
  printf("vector:\t\t\t");
  print_bytes_int(session->vector, sizeof(session->vector));
  printf("\n");
  printf("rounds:\t\t\t%u\n", session->rounds);
  printf("rest:\t\t\t%zu bytes", session->rest_size);
  // printf("rest: ");
  // print_bytes_int(session->rest, session->rest_size);
  printf("\n");
  printf("hmac_sha256:\t\t");
  print_bytes_int(session->hmac_sha256, sizeof(session->hmac_sha256));
  printf("\n");
}
