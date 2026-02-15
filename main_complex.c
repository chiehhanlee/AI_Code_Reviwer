#include <stdio.h>
#include <stdlib.h>
#include "user_manager.h"

int main() {
    printf("Starting User Manager System...\n");

    User *alice = create_user(1, "Alice", "password123");
    
    // Simulate some operations
    process_user_command(alice, "login");

    // Vulnerability 1: Use-After-Free
    delete_user(alice);
    
    // Attacker might trigger an allocation here that occupies the freed memory
    // char *p = malloc(sizeof(User)); 
    
    // Logic error: accessing alice after free
    printf("Attempting to process subsequent command...\n");
    // This is defined behavior: undefined. But common UAF pattern.
    process_user_command(alice, "logout"); 

    // Vulnerability 2: Double Free
    // Calling delete_user again on the same pointer
    delete_user(alice);

    return 0;
}
