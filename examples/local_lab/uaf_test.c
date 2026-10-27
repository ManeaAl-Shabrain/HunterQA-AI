#include <stdio.h>
#include <stdlib.h>
/* Deliberate, locally isolated heap-use-after-free for ASan demonstration. */
int main(void) {
    int *data = malloc(sizeof(*data));
    if (!data) return 1;
    *data = 100;
    free(data);
    printf("%d\n", *data);
    return 0;
}
