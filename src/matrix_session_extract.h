#include <Python.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_LEN (16)
#define VECTOR_LEN (16)
#define ROUNDS_LEN (4)
#define HMAC_SHA256_LEN (32)

typedef struct ParsedSession {
  char salt[SALT_LEN];
  char vector[VECTOR_LEN];
  uint32_t rounds;
  char *rest;
  size_t rest_size;
  char hmac_sha256[HMAC_SHA256_LEN];
} ParsedSession;

ParsedSession *session_parse(FILE *fp);
const unsigned char *calc_aes_key(const char *passphrase, const size_t rounds,
                                  const char *salt);
void print_bytes(const char *bytes, const size_t len);
void print_hex_bytes(const char *bytes, const size_t len);
void print_uint8(const u_int8_t *bytes, const size_t len);