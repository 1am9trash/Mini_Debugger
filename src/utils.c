#include <string.h>

#include "utils.h"

// 0: false, 1: true
uint32_t is_prefix(const char *prefix, const char *str) {
    if (strlen(prefix) > strlen(str)) return 0;
    return strncmp(prefix, str, strlen(prefix)) == 0;
}

// n: number of arguments
uint32_t split_str(char *str, char **argv, uint32_t len) {
    static const char *delim = " \n";

    argv[0] = strtok(str, delim);
    if (argv[0] == NULL) {
        return 0;
    }
    for (uint32_t i = 1; i < len; i++){
        argv[i] = strtok(NULL, delim);
        if (argv[i] == NULL) {
            return i;
        }
    }
    return len;
}