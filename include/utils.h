#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdint.h>

#define BLACK "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"

#define DEBUG 1

#ifdef DEBUG
#define DEBUG_PRINT(...) do { fprintf(stderr, RED __VA_ARGS__); fprintf(stderr, BLACK);} while (0)
#else
#define DEBUG_PRINT(...) do { } while (0)
#endif

uint32_t is_prefix(const char *prefix, const char *str);
uint32_t split_str(char *str, char **argv, uint32_t len);

#endif