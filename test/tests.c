#include "../src/matrix_session_extract.h"

void test_parse();
void test_print_to_file();
void test_calc_aes_key();

int main() {
  test_parse();
  // test_calc_aes_key();
}

void test_parse() {
  ParsedSession *session = session_parse_alloc(stdin);
  print_session(session);

  char salt[SALT_LEN] = {
      -23, 90, 59, 0, -58, 33, -22, 43, 79, -38, 41, -38, 31, 33, -73, -90, 0,
  };
  char vector[VECTOR_LEN] = {
      -27, 43, -9, 83, 2, -114, 103, 83, -48, -105, 95, -17, -50, 56, 61,
  };

  char hmac_sha[HMAC_SHA256_LEN] = {
      -7,  -5,  -43, -81, -11, 54,  -32, -98, 127, 14,   -24,
      115, 102, -8,  7,   18,  78,  -5,  -18, 44,  -108, -29,
      69,  -81, 49,  -98, -98, -44, 107, -70, 24,  -50,
  };

  uint32_t rounds = 500000;

  // TODO: asserts (also rest)

  free(session->rest);
  free(session);
}

void test_print_to_file() {
  // TODO
}

void test_calc_aes_key() {
  char *salt = "ßZ;Ô!ê+OÝ)Ú!·¨";
  char *passphrase = "testus";
  uint32_t rounds = 500000;

  const unsigned char *aes_key = calc_aes_key(passphrase, rounds, salt);

  const unsigned char chrs[65] = {
      36,  183, 144, 195, 202, 190, 234, 254, 33,  126, 14,  78,  207,
      233, 146, 6,   171, 227, 83,  24,  26,  36,  27,  241, 73,  10,
      187, 27,  42,  68,  108, 152, 23,  230, 132, 163, 144, 201, 36,
      84,  74,  124, 117, 143, 120, 179, 217, 230, 87,  239, 227, 230,
      72,  168, 57,  64,  185, 132, 168, 83,  75,  80,  238, 97,  0,
  };

  assert(!strcmp((char *)aes_key, (char *)chrs));
}
