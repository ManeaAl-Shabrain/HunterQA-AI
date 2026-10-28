#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int *data = malloc(sizeof(int));

    if (data == NULL)
        return 1;

    *data = 100;

    free(data);

    printf("Value: %d\n", *data);

    return 0;
}
