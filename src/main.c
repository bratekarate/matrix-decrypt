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

  ParsedSession *res = malloc(sizeof(ParsedSession));
  res = session_parse(fp);

  fp = fopen(argv[1], "w");
  for (size_t k = 0; k < res->rest_size; k++) {
    fputc(res->rest[k], fp);
  }

  fclose(fp);

  const unsigned char *aes_key = calc_aes_key(argv[2], res->rounds, res->salt);

  // print resulting key and initialization vector
  for (size_t c = 0; c < AES_KEY_LEN; c++) {
    printf("%02x", aes_key[c]);
  }
  printf(" ");

  for (size_t c = 0; c < VECTOR_LEN; c++) {
    printf("%02x", (const unsigned char)(res->vector[c]));
  }
  printf("\n");

  return EXIT_SUCCESS;
}
