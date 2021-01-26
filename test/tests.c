#include "../src/matrix_session_extract.h"

void test_parse();
void test_print_to_file();
void test_calc_aes_key();

int main () {
    test_parse();
}

void test_parse(){
    ParsedSession *session = session_parse_alloc(stdin);
    print_session(session);

    free(session->rest);
    free(session);
}

void test_print_to_file() {
    // TODO
}

void test_calc_aes_key() {
    // TODO
}
