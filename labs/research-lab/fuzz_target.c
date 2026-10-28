#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char input[128] = {0};

    size_t n = fread(input, 1, sizeof(input), stdin);

    if (n >= 4 && memcmp(input, "FUZZ", 4) == 0) {
        if (n >= 8 && memcmp(input + 4, "TEST", 4) == 0) {
            if (n >= 12 && memcmp(input + 8, "2026", 4) == 0) {
                abort();
            }
        }
    }

    return 0;
}
