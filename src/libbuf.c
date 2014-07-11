#include <stdlib.h>

char *get_buf(int n) {
    return (char *) malloc(n * sizeof(char));
}
