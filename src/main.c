#include <stdint.h>

#include "debugger.h"

uint32_t main(uint32_t argc, char *argv[]) {
    run_main_loop(argc, argv);

    return 0;
}