#include "./matrix_session_extract.h"

int main(int argc, char *argv[]) {

  FILE *fp;

  switch (argc) {
  case 3:
    fp = stdin;
    break;
  case 4:
    fp = fopen(argv[3], "r");
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

  printf("%s\n", decr);

  free(decr);
  decr = NULL;

  return EXIT_SUCCESS;
}
