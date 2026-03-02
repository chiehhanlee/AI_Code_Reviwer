#ifndef USER_MANAGER_H
#define USER_MANAGER_H

typedef struct {
    int id;
    char *username;
    char *password;
    int priv_level;
} User;

// Function prototypes
User* create_user(int id, const char *username, const char *password);
void delete_user(User *user);
void process_user_command(User *user, char *cmd);
void db_connect(); // Simulated database connection

#endif // USER_MANAGER_H
