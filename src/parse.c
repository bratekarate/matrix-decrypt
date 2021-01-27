#include "./matrix_session_extract.h"

ParsedSession *session_parse_alloc(FILE *fp) {
  ParsedSession *res = malloc(sizeof(ParsedSession));

  res->format = fgetc(fp);

  size_t i;
  for (i = 0; i < SALT_LEN - 1; i++) {
    res->salt[i] = fgetc(fp);
  }
  res->salt[i] = '\0'; // \0 character necessary for python object conversion

  for (i = 0; i < VECTOR_LEN; i++) {
    res->vector[i] = fgetc(fp);
  }

  u_int8_t rnd_arr[ROUNDS_LEN];
  for (i = 0; i < ROUNDS_LEN; i++) {
    rnd_arr[i] = fgetc(fp);
  }

  res->rounds =
      (rnd_arr[0] << 24) + (rnd_arr[1] << 16) + (rnd_arr[2] << 8) + rnd_arr[3];

  i = 0;
  res->rest = malloc(0);
  char buf;
  printf("%s\n", "parsing");
  while (!feof(fp)) {
    res->rest = realloc(res->rest, i + 1);
    res->rest[i] = fgetc(fp);
    i++; // TODO: why is i after loop the size of rest bytes + 1?
  }

  fclose(fp);

  if (i < HMAC_SHA256_LEN + 1) {
    fprintf(stderr, "Error: File content is too short.");
    exit(1);
  }

  i--; // see TODO above

  size_t j;
  for (j = 0; j < HMAC_SHA256_LEN; j++) {
    res->hmac_sha256[HMAC_SHA256_LEN - 1 - j] = res->rest[i - 1 - j];
  }

  res->rest_size = i - j;

  return res;
}
