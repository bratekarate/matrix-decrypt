#include "../src/matrix_session_extract.h"

#define REST_SIZE (100000)
#define ALPHA_MIN (-122)
#define ALPHA_MAX (122)
#define TMP_PATH ("/tmp/matrix_test_out")
#define TOTAL_SIZE                                                             \
  (1 + REST_SIZE + SALT_LEN - 1 + VECTOR_LEN + ROUNDS_LEN + HMAC_SHA256_LEN)

void test_parse();
void test_print_to_file();
void test_calc_aes_key();

int main() {
  test_parse();
  test_calc_aes_key();
}

void test_parse() {
  char *str = malloc(TOTAL_SIZE * sizeof(char));
  char *strptr = str;

  char format = 1;
  *strptr++ = format;
  char salt[SALT_LEN - 1] = {
      -23, 90, 59, 0, -58, 33, -22, 43, 79, -38, 41, -38, 31, 33, -73, -90,
  };

  memcpy(strptr, &salt, SALT_LEN - 1);
  strptr += SALT_LEN - 1;

  char vector[VECTOR_LEN] = {
      -27, 43, -9, 83, 2, -114, 103, 83, -48, -105, 95, -17, -50, 56, 61,
  };

  memcpy(strptr, &vector, VECTOR_LEN);
  strptr += VECTOR_LEN;

  uint32_t rounds = 500000;
  uint8_t rounds_arr[ROUNDS_LEN];
  {
    int32_t rounds_tmp = rounds;
    rounds_arr[0] = rounds_tmp >> 24;
    rounds_arr[1] = rounds_tmp >> 16;
    rounds_arr[2] = rounds_tmp >> 8;
    rounds_arr[3] = rounds_tmp;
  }

  memcpy(strptr, &rounds_arr, ROUNDS_LEN);
  strptr += ROUNDS_LEN;
  char *restptr = strptr;

  for (size_t i = 0; i < REST_SIZE; i++) {
    (*strptr++) = -26;
  }

  char hmac_sha[HMAC_SHA256_LEN] = {
      -7,  -5,  -43, -81, -11, 54,  -32, -98, 127, 14,   -24,
      115, 102, -8,  7,   18,  78,  -5,  -18, 44,  -108, -29,
      69,  -81, 49,  -98, -98, -44, 107, -70, 24,  -50,
  };

  memcpy(strptr, &hmac_sha, HMAC_SHA256_LEN);
  strptr += HMAC_SHA256_LEN;

  assert(strptr - str == TOTAL_SIZE);

  FILE *fp = fopen(TMP_PATH, "w");

  for (size_t i = 0; i < TOTAL_SIZE; i++) {
    fputc(str[i], fp);
  }

  fclose(fp);

  fp = fopen(TMP_PATH, "r");
  ParsedSession *session = session_parse_alloc(fp);
  remove(TMP_PATH);

  // print_session(session);

  assert(!memcmp(&session->format, &format, sizeof(char)));
  assert(!memcmp(session->salt, salt, SALT_LEN - 1 * sizeof(char)));
  assert(!memcmp(session->vector, vector, VECTOR_LEN * sizeof(char)));
  assert(session->rounds == rounds);
  assert(
      !memcmp(session->hmac_sha256, hmac_sha, HMAC_SHA256_LEN * sizeof(char)));
  assert(!memcmp(session->rest, restptr, REST_SIZE * sizeof(char)));

  free(session->rest);
  free(session);
}

void test_calc_aes_key() {
  char salt[] = {
      -23, 90, 59, 0, -58, 33, -22, 43, 79, -38, 41, -38, 31, 33, -73, -90, 0,
  };

  char *passphrase = "testus";

  uint32_t rounds = 500000;

  const unsigned char *aes_key = calc_aes_key(passphrase, rounds, salt);

  const unsigned char chrs[] = {
      115, 24,   -70,  -35, -59, -57, -112, -58,  -42,  1,   -53, 70,   -4,
      89,  17,   116,  47,  87,  80,  -57,  109,  -5,   -65, 55,  -118, -84,
      -93, -118, 53,   17,  127, 127, -47,  -77,  119,  -29, 102, 92,   -60,
      41,  22,   112,  -51, -92, 5,   -66,  67,   -15,  86,  72,  -23,  90,
      -50, 108,  -103, -26, 100, 120, -78,  -100, -114, 41,  99,  4,    0,
  };

  assert(!strcmp((char *)aes_key, (char *)chrs));
}
