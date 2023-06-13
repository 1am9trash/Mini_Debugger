#ifndef _DEBUGGER_H_
#define _DEBUGGER_H_

#include <stdint.h>
#include <sys/wait.h>

#include "linked_list.h"

// data

struct Breakpoint {
    uint64_t save_instruction;
    uint64_t addr;
    uint32_t is_enable;
};

struct Debugger {
    pid_t pid;
    struct ListEntry *breakpoints_head;
    struct Breakpoint *breakpoint_callback;
};

struct RegisterDescriptor {
    char name[10];
    uint32_t offset;
};

extern const uint32_t num_regs;
extern const struct RegisterDescriptor reg_list[];

// process function
void run_main_loop(uint32_t argc, char *argv[]);
uint32_t handle_command(struct Debugger *debugger, char *cmd);

// signal
siginfo_t get_signal_info(struct Debugger *debugger);
void wait_for_signal(struct Debugger *debugger);
void handle_sigtrap(struct Debugger *debugger, siginfo_t info);

// quit
void do_quit(struct Debugger *debugger);

// step
void do_step(struct Debugger *debugger);

// continue
void do_continue(struct Debugger *debugger);

// register
int32_t find_register_index(char *name);
uint32_t get_register(struct Debugger *debugger, char *name, uint64_t *value);
uint32_t set_register(struct Debugger *debugger, char *name, uint64_t value);
void dump_registers(struct Debugger *debugger);

// memory
void get_memory(struct Debugger *debugger, uint64_t addr, uint64_t *value);
void set_memory(struct Debugger *debugger, uint64_t addr, uint64_t value);

// breakpoint
uint32_t breakpoint_cmp(void *a, void *b);
struct Breakpoint *is_breakpoint_exit(struct Debugger *debugger, uint64_t addr);
uint32_t add_breakpoint(struct Debugger *debugger, uint64_t addr);
uint32_t enable_breakpoint(struct Debugger *debugger, struct Breakpoint *breakpoint);
uint32_t disable_breakpoint(struct Debugger *debugger, struct Breakpoint *breakpoint);
uint32_t enable_breakpoint_by_addr(struct Debugger *debugger, uint64_t addr);
uint32_t disable_breakpoint_by_addr(struct Debugger *debugger, uint64_t addr);
uint32_t do_breakpoint(struct Debugger *debugger, uint64_t addr);

// asm
void read_asm(struct Debugger *debugger);

#endif