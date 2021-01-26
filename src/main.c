#include "./matrix_session_extract.h"

#define AES_KEY_LEN (64)

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

  write_to_file(argv[1], session->rest, session->rest_size);

  free(session->rest);
  session->rest = NULL;

  fclose(fp);
  fp = NULL;

  const unsigned char *aes_key =
      calc_aes_key(argv[2], session->rounds, session->salt);

  // print resulting key and initialization vector
  for (size_t c = 0; c < AES_KEY_LEN; c++) {
    printf("%02x", aes_key[c]);
  }
  printf(" ");

  for (size_t c = 0; c < VECTOR_LEN; c++) {
    printf("%02x", (const unsigned char)(session->vector[c]));
  }
  printf("\n");

  free(session);
  session = NULL;

  return EXIT_SUCCESS;
}
