#include "./matrix_session_extract.h"

ParsedSession *session_parse(FILE *fp) {
  const char format = fgetc(fp);

  size_t i;
  char salt[SALT_LEN + 1];
  for (i = 0; i < SALT_LEN; i++) {
    salt[i] = fgetc(fp);
  }
  salt[i] = '\0'; // \0 character necessary for python object conversion

  char vec[VECTOR_LEN];
  for (i = 0; i < VECTOR_LEN; i++) {
    vec[i] = fgetc(fp);
  }

  u_int8_t rnd_arr[ROUNDS_LEN];
  for (i = 0; i < ROUNDS_LEN; i++) {
    rnd_arr[i] = fgetc(fp);
  }

  i = 0;
  char *rest = malloc(0);
  char buf;
  while (!feof(fp)) {
    rest = realloc(rest, i + 1);
    rest[i] = fgetc(fp);
    i++; // TODO: why is i after loop the size of rest bytes + 1?
  }

  fclose(fp);

  if (i < HMAC_SHA256_LEN + 1) {
    fprintf(stderr, "Error: File content is too short.");
    exit(1);
  }

  i--; // see TODO above

  char hmac_sha256[HMAC_SHA256_LEN];
  size_t j;
  for (j = 0; j < HMAC_SHA256_LEN; j++) {
    hmac_sha256[HMAC_SHA256_LEN - 1 - j] = rest[i - 1 - j];
  }

  i -= j;

  const uint32_t rounds =
      (rnd_arr[0] << 24) + (rnd_arr[1] << 16) + (rnd_arr[2] << 8) + rnd_arr[3];

  ParsedSession *res = malloc(sizeof(ParsedSession));
  memcpy(res->salt, salt, sizeof(res->salt));
  memcpy(res->vector, vec, sizeof(res->vector));
  res->rounds = rounds;
  memcpy(res->hmac_sha256, hmac_sha256, sizeof(res->hmac_sha256));
  memcpy(res->rest, rest, i);

  return res;
}
