#include "./matrix_session_extract.h"

int main(int argc, char *argv[]) {

  FILE *fp;

  switch (argc) {
  case 4:
    fp = stdin;
    break;
  // TODO: fix file argument
  case 5:
    fp = fopen(argv[4], "r");
    break;
  default:
    fprintf(stderr,
            "Error: Need at least a passphrase and an output filepath.\n");
    exit(1);
    break;
  }

  if (fp == NULL) {
    perror("Error");
    return 1;
  }

  ParsedSession *session = session_parse_alloc(fp);

  fclose(fp);
  fp = NULL;

  fp = fopen(argv[1], "w");
  for (size_t k = 0; k < session->rest_size; k++) {
    fputc(session->rest[k], fp);
  }

  fclose(fp);
  fp = NULL;

  unsigned char aes_key[AES_KEY_LEN];

  calc_aes_key(argv[2], session->rounds, session->salt, aes_key, AES_KEY_LEN);

  unsigned char *decr =
      malloc((session->rest_size + 16) * sizeof(unsigned char));
  size_t plain_len = decrypt((unsigned char *)session->rest, session->rest_size,
                             aes_key, (unsigned char *)session->vector, decr);

  free(session->rest);
  session->rest = NULL;

  free(session);
  session = NULL;

  // printf("%s\n", decr);
  //
  fp = fopen(argv[3], "r");

  size_t buf_size = 500;
  char *enc_msgs = malloc(buf_size * sizeof(char));

  size_t content_i = 0;
  char buf;
  while ((buf = fgetc(fp)) != EOF) {
    if ((content_i + 1) * sizeof(char) > buf_size) {
      buf_size *= 1.5;
      enc_msgs = realloc(enc_msgs, buf_size * sizeof(char));
    }
    enc_msgs[content_i++] = buf;
  }

  // char *enc_msgs = "[]";
  size_t msg_len = strlen(enc_msgs);

  cJSON *msgs_json = cJSON_ParseWithLength(enc_msgs, msg_len);

  // printf("%s\n", cJSON_Print(msgs_json));

  size_t msgs_len = cJSON_GetArraySize(msgs_json);

  char **plaintext_msgs = malloc(msgs_len * sizeof(char *));
  char **plaintext_ptr =
      decrypt_olm((char *)decr, plain_len, enc_msgs, content_i, plaintext_msgs);

  // while (plaintext_msgs < plaintext_ptr) {
  //   printf("%s\n", *plaintext_msgs++);
  // }

  free(decr);
  decr = NULL;

  return EXIT_SUCCESS;
}
