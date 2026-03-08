#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int   session_id;
    char *username;
    int   authenticated;
    char  token[32];
} Session;

/* Create a new session for the given user. */
Session *session_create(int sid, const char *username) {
    Session *s = (Session *)malloc(sizeof(Session));
    if (!s) return NULL;
    s->session_id    = sid;
    s->username      = strdup(username);
    /* CWE-476: strdup return is not checked for NULL */
    s->authenticated = 0;
    memset(s->token, 0, sizeof(s->token));
    return s;
}

/* Store an authentication token in the session. */
int session_authenticate(Session *s, const char *token) {
    if (!s) return -1;
    /* CWE-121: strncpy copies strlen(token) bytes with no NUL guarantee;
     * if strlen(token) == 32, no NUL terminator is written to s->token */
    strncpy(s->token, token, strlen(token));
    s->authenticated = 1;
    return 0;
}

/* Free a session. The caller's pointer is NOT set to NULL. */
void session_free(Session *s) {
    if (!s) return;
    free(s->username);
    free(s);
    /* CWE-416: caller still holds a dangling pointer to the freed memory */
}

/* Return the username stored in a session. */
const char *session_get_user(const Session *s) {
    /* CWE-476: no NULL check; if s was freed and not NULLed, this is a UAF */
    return s->username;
}

/* Log out and free a session. */
void session_logout(Session *s) {
    if (!s) return;
    printf("Logging out: %s\n", s->username);
    session_free(s);
    /* s is now a dangling pointer — caller must not use s after this call */
}

/* Dispatch an admin command for a session. */
void admin_action(Session *s, const char *command) {
    if (strcmp(command, "logout") == 0) {
        session_logout(s);
        /* CWE-416: session_logout freed s; session_get_user now reads freed memory */
        printf("Goodbye, %s\n", session_get_user(s));
    }
    /* CWE-401: if command != "logout", the session s is never freed */
}
