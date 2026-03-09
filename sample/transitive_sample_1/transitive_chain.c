#include <string.h>
#include <stdio.h>
#include <unistd.h>

/*
 * Three-level transitive vulnerability chain:
 *   handle_request  ->  process_input  ->  unsafe_copy
 *
 * No single-function review can catch the stack overflow:
 *   - handle_request looks safe (read is bounded to sizeof(input)-1 = 255 bytes)
 *   - process_input looks safe (it delegates the copy to a helper)
 *   - unsafe_copy looks like it trusts the caller for sizing
 *
 * The bug is only visible when all three functions are analysed together:
 * handle_request passes up to 255 bytes to process_input whose local_buf is
 * only 64 bytes, and unsafe_copy performs strcpy without any bounds check.
 */

/* Level 3: copies src into dst without any bounds check. */
static void unsafe_copy(char *dst, const char *src)
{
    strcpy(dst, src);
}

/* Level 2: stack buffer is 64 bytes; user_data may be much larger. */
static void process_input(const char *user_data)
{
    char local_buf[64];
    unsafe_copy(local_buf, user_data);
    printf("processed: %s\n", local_buf);
}

/* Level 1: reads up to 255 bytes from fd and passes it to process_input. */
void handle_request(int fd)
{
    char input[256];
    ssize_t n = read(fd, input, sizeof(input) - 1);
    if (n <= 0)
        return;
    input[n] = '\0';
    process_input(input);
}
