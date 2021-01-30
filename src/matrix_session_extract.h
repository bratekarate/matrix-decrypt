#include <inttypes.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define SALT_LEN (17)
#define VECTOR_LEN (16)
#define ROUNDS_LEN (4)
#define HMAC_SHA256_LEN (32)
#define AES_KEY_LEN (64)

typedef struct ParsedSession {
  char format;
  char salt[SALT_LEN];
  char vector[VECTOR_LEN];
  uint32_t rounds;
  char *rest;
  size_t rest_size;
  char hmac_sha256[HMAC_SHA256_LEN];
} ParsedSession;

ParsedSession *session_parse_alloc(FILE *fp);
void write_to_file(char *filepath, char *rest, size_t rest_size);
void calc_aes_key(const char *passphrase, const size_t rounds, const char *salt,
                  unsigned char *out, size_t out_size);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
void print_bytes(const char *bytes, const size_t len);
void print_bytes_int(const char *bytes, const size_t len);
void print_hex_bytes(const char *bytes, const size_t len);
void print_uint8(const u_int8_t *bytes, const size_t len);
void print_session(ParsedSession *session);
