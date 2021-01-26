#include "matrix_session_extract.h"

void print_bytes(const char *bytes, const size_t len) {
  for (int i = 0; i < len; i++) {
    printf("%c", bytes[i]);
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
  printf("salt: ");
  print_bytes(session->salt, sizeof(session->salt));
  printf("\n");
  printf("vector: ");
  print_bytes(session->vector, sizeof(session->vector));
  printf("\n");
  printf("rounds: %u\n", session->rounds);
  printf("rest: %zu bytes", session->rest_size);
  /*print_bytes(session->rest, session->rest_size);*/
  printf("\n");
  printf("hmac_sha256: ");
  print_bytes(session->hmac_sha256, sizeof(session->hmac_sha256));
  printf("\n");
}

void write_to_file(char *filepath, char *rest, size_t rest_size) {
  FILE *fp = fopen(filepath, "w");
  for (size_t k = 0; k < rest_size; k++) {
    fputc(rest[k], fp);
  }
}
