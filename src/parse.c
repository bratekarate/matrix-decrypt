#include "./matrix_session_extract.h"

ParsedSession *session_parse_alloc(FILE *fp) {
  ParsedSession *session = malloc(sizeof(ParsedSession));

  {
    char buf[100];
    fgets(buf, 100, fp);
  }

  size_t buf_size = 500;
  char *content = malloc(buf_size * sizeof(char));

  size_t content_i = 0;
  char buf;
  while ((buf = fgetc(fp)) != EOF) {
    if (buf != '\n') {
      if ((content_i + 1) * sizeof(char) > buf_size) {
        buf_size *= 1.5;
        content = realloc(content, buf_size * sizeof(char));
      }
      content[content_i++] = buf;
    }
  }

  const size_t payload_size = (content_i - 33) * sizeof(char);
  char *stripped = malloc(payload_size);
  memcpy(stripped, content, payload_size);

  unsigned char *decoded = malloc(payload_size);
  int size = b64_pton((const char *)stripped, decoded, payload_size);

  unsigned char *dec_pointer = decoded;
  session->format = *dec_pointer++;

  for (size_t i = 0; i < SALT_LEN - 1; i++) {
    session->salt[i] = *dec_pointer++;
  }
  session->salt[SALT_LEN - 1] =
      '\0'; // \0 character necessary for python object conversion

  for (size_t i = 0; i < VECTOR_LEN; i++) {
    session->vector[i] = *dec_pointer++;
  }

  u_int8_t rnd_arr[ROUNDS_LEN];
  for (size_t i = 0; i < ROUNDS_LEN; i++) {
    rnd_arr[i] = *dec_pointer++;
  }

  session->rounds =
      (rnd_arr[0] << 24) + (rnd_arr[1] << 16) + (rnd_arr[2] << 8) + rnd_arr[3];
  session->rest = malloc(sizeof(char));

  size_t rest_i;
  for (rest_i = 0; rest_i < size + 1 - SALT_LEN - VECTOR_LEN - ROUNDS_LEN;
       rest_i++) {
    session->rest = realloc(session->rest, (rest_i + 1) * sizeof(char));
    session->rest[rest_i] = *dec_pointer++;
  }
  // TODO: why is i after loop the size of rest bytes + 1?

  if (rest_i < HMAC_SHA256_LEN + 1) {
    fprintf(stderr, "Error: File content is too short.");
    exit(1);
  }

  rest_i--; // see TODO above

  for (size_t i = 0; i < HMAC_SHA256_LEN; i++) {
    session->hmac_sha256[HMAC_SHA256_LEN - 1 - i] =
        session->rest[rest_i - 1 - i];
  }

  session->rest_size = rest_i - HMAC_SHA256_LEN;

  return session;
}
