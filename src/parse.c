#include "./matrix_session_extract.h"

ParsedSession *session_parse_alloc(FILE *fp) {
  ParsedSession *session = malloc(sizeof(ParsedSession));

  char fstline[1000];
  fgets(fstline, 1000, fp);

  char *content = malloc(1 * sizeof(char));
  size_t content_size = 0;

  char chr;
  while ((chr = fgetc(fp)) != EOF) {
    if (chr != '\n') {
      content = realloc(content, (content_size + 1) * sizeof(char));
      content[content_size++] = chr;
    }
  }

  char *stripped = malloc((content_size - 33) * sizeof(char));
  memcpy(stripped, content, (content_size - 33) * sizeof(char));

  unsigned char *decoded = malloc((content_size - 33) * sizeof(char));
  int size = b64_pton((const char *)stripped, decoded, (content_size - 33) * sizeof(char));

  fclose(fp);

  fp = fopen("/tmp/decoded", "w");
  for (size_t i = 0; i < size; i++) {
    fputc(decoded[i], fp);
  }

  fclose(fp);

  fp = fopen("/tmp/decoded", "r");

  session->format = fgetc(fp);

  size_t i;
  for (i = 0; i < SALT_LEN - 1; i++) {
    session->salt[i] = fgetc(fp);
  }
  session->salt[i] = '\0'; // \0 character necessary for python object conversion

  for (i = 0; i < VECTOR_LEN; i++) {
    session->vector[i] = fgetc(fp);
  }

  u_int8_t rnd_arr[ROUNDS_LEN];
  for (i = 0; i < ROUNDS_LEN; i++) {
    rnd_arr[i] = fgetc(fp);
  }

  session->rounds =
      (rnd_arr[0] << 24) + (rnd_arr[1] << 16) + (rnd_arr[2] << 8) +
      rnd_arr[3];

  i = 0;
  session->rest = malloc(0);
  char buf;
  while (!feof(fp)) {
    session->rest = realloc(session->rest, i + 1);
    session->rest[i] = fgetc(fp);
    i++; // TODO: why is i after loop the size of rest bytes + 1?
  }

  fclose(fp);
  remove("/tmp/decoded");

  if (i < HMAC_SHA256_LEN + 1) {
    fprintf(stderr, "Error: File content is too short.");
    exit(1);
  }

  i--; // see TODO above

  size_t j;
  for (j = 0; j < HMAC_SHA256_LEN; j++) {
    session->hmac_sha256[HMAC_SHA256_LEN - 1 - j] = session->rest[i - 1 - j];
  }

  session->rest_size = i - j;

  return session;
}
