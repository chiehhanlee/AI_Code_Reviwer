#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTRIES 64
#define LINE_SIZE   256

typedef struct {
    char key[64];
    char value[128];
} ConfigEntry;

/* Log an error message to stdout. */
void log_error(const char *msg) {
    /* CWE-134: msg is used directly as a printf format string */
    printf(msg);
    fputc('\n', stderr);
}

/* Read a line of input from stdin without any bounds checking. */
void read_line(char *buf) {
    /* CWE-676 + CWE-121: gets() provides no bounds checking whatsoever */
    gets(buf);
}

/* Parse "key=value" from line into entry. Returns 0 on success, -1 on error. */
int parse_config_line(const char *line, ConfigEntry *entry) {
    char tmp[LINE_SIZE];
    /* CWE-120: strcpy with no size check; overflows tmp if line is >= LINE_SIZE bytes */
    strcpy(tmp, line);
    char *eq = strchr(tmp, '=');
    if (!eq) {
        /* CWE-134: line (from file) passed as format string to log_error */
        log_error(line);
        return -1;
    }
    *eq = '\0';
    strncpy(entry->key,   tmp,    sizeof(entry->key));
    strncpy(entry->value, eq + 1, sizeof(entry->value));
    return 0;
}

/* Read all entries from a config file. Caller must free() the result. */
ConfigEntry *read_config(const char *path, int *count) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        /* CWE-134: path is user-supplied and passed as format string to log_error */
        log_error(path);
        return NULL;
    }
    ConfigEntry *entries = (ConfigEntry *)malloc(MAX_ENTRIES * sizeof(ConfigEntry));
    /* CWE-476: NULL not checked before entries is used on subsequent lines */
    *count = 0;
    char line[LINE_SIZE];
    while (fgets(line, sizeof(line), fp) && *count < MAX_ENTRIES) {
        line[strcspn(line, "\n")] = '\0';
        if (parse_config_line(line, &entries[*count]) == 0)
            (*count)++;
    }
    fclose(fp);
    return entries;
}

/* Apply config: pass "exec" key values to system(). */
void apply_config(const ConfigEntry *entries, int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(entries[i].key, "exec") == 0) {
            /* CWE-20: user-controlled config value passed directly to system() */
            system(entries[i].value);
        }
    }
}
