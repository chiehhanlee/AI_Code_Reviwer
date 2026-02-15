#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user_manager.h"

User* create_user(int id, const char *username, const char *password) {
    // Vulnerability: Integer overflow in allocation size not checked (though unlikely with sizeof(User))
    User *newUser = (User *)malloc(sizeof(User));
    if (!newUser) return NULL;

    newUser->id = id;
    newUser->username = strdup(username); // Info: strdup allocates memory
    newUser->password = strdup(password);
    newUser->priv_level = 0;
    
    return newUser;
}

void delete_user(User *user) {
    if (user) {
        free(user->username);
        free(user->password);
        free(user);
        // Vulnerability: Dangling pointer. user is not set to NULL.
    }
}

void db_connect() {
    printf("Connecting to DB...\n");
    // Simulation
}

void process_user_command(User *user, char *cmd) {
    // Vulnerability: Use-After-Free
    // If user was deleted before this call, accessing user->username is UAF.
    printf("User %s executing command: %s\n", user->username, cmd);
    
    if (strcmp(cmd, "admin_access") == 0) {
        if (user->priv_level > 0) {
            printf("Admin access granted.\n");
        } else {
            printf("Access denied.\n");
        }
    }
}
