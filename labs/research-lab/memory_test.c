#include <stdlib.h>

int main(void) {
    int *data = malloc(sizeof(int));
    if (!data) return 1;

    free(data);
    return 0;
}
