#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[100];
    // Vulnerability 1: Buffer Overflow
    // strcpy doesn't check the size of the destination buffer
    strcpy(buffer, input);
    
    printf("Input received: ");
    // Vulnerability 2: Format String Vulnerability
    // If input contains format specifiers like %x, %n, etc., it will leak stack data or crash
    printf(buffer);
    printf("\n");
}

void integer_overflow_example(int count) {
    // Vulnerability 3: Integer Overflow
    // If count is large enough, count * sizeof(int) can wrap around to a small number
    size_t size = count * sizeof(int);
    int *arr = (int *)malloc(size);
    
    if (arr) {
        for (int i = 0; i < count; i++) {
            arr[i] = i; // Heap buffer overflow if size wrapped around
        }
        free(arr);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    printf("Running vulnerable function...\n");
    vulnerable_function(argv[1]);

    printf("Running integer overflow example...\n");
    // Just a demonstration value, in a real attack this would be crafted
    integer_overflow_example(100); 

    return 0;
}
