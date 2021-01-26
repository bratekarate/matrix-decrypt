#include "../src/matrix_session_extract.h"

int main () {
    printf("Running tests\n");
    print_session(session_parse(fopen("/tmp/element-keys.txt", "r")));
}
