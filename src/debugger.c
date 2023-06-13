#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <capstone/capstone.h>

#include "utils.h"
#include "debugger.h"

#define INT3 0xcc

const uint32_t num_regs = 27;
const struct RegisterDescriptor reg_list[27] = {
    {"r15", 0},
    {"r14", 1},
    {"r13", 2},
    {"r12", 3},
    {"rbp", 4},
    {"rbx", 5},
    {"r11", 6},
    {"r10", 7},
    {"r9", 8},
    {"r8", 9},
    {"rax", 10},
    {"rcx", 11},
    {"rdx", 12},
    {"rsi", 13},
    {"rdi", 14},
    {"orig_rax", 15},
    {"rip", 16},
    {"cs", 17},
    {"eflags", 18},
    {"rsp", 19},
    {"ss", 20},
    {"fs_base", 21},
    {"gs_base", 22},
    {"ds", 23},
    {"es", 24},
    {"fs", 25},
    {"gs", 26}
};

// process function
void run_main_loop(uint32_t argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: debugger program\n");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        char *program_name = argv[1];
        char **program_arg;
        
        program_arg = malloc(argc * sizeof(char *));
        for (uint32_t i = 1; i < argc; i++) {
            program_arg[i - 1] = argv[i];
        }
        argv[argc - 1] = NULL;

        fprintf(stdout, "forked child process\n");

        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(program_name, program_arg);
    } else if (pid > 0) {
        fprintf(stdout, "parent process\n");
        fprintf(stdout, "child process pid is %d\n", pid);

        struct Debugger debugger;
        debugger.pid = pid;
        debugger.breakpoints_head = NULL;
        debugger.breakpoint_callback = NULL;

        wait_for_signal(&debugger);

        // set command length limit to 100 chars
        char cmd[100];
        fprintf(stdout, GREEN "debugger> " BLACK);
        while ((fgets(cmd, 100, stdin)) != NULL) {
            if (handle_command(&debugger, cmd)) {
                fprintf(stdout, GREEN "debugger> " BLACK);
            } else {
                break;
            }
        }
    }
}

// 0: quit, 1: continue
uint32_t handle_command(struct Debugger *debugger, char *cmd) {
    if (cmd == NULL) {
        return 1;
    }

    // set command length limit to 100 words
    char *argv[100];
    uint32_t argc;
    argc = split_str(cmd, argv, 100);

    if (argc == 0) {
        return 1;
    }

    if (is_prefix(argv[0], "help")) {
        fprintf(stdout, "help       -- show all command usage\n");
        fprintf(stdout, "quit       -- close the subprocess and end the debugger\n");
        fprintf(stdout, "breakpoint -- set a breakpoint at specified address\n");
        fprintf(stdout, "register   -- read/write registers\n");
        fprintf(stdout, "memory     -- read/write memory \n");
        fprintf(stdout, "step       -- execute an instruction \n");
        fprintf(stdout, "continue   -- run until the next breakpoint is encountered\n");
        fprintf(stdout, "asm        -- show instructions\n");
    } else if (is_prefix(argv[0], "quit")) {
        do_quit(debugger);
        return 0;
    } else if (is_prefix(argv[0], "breakpoint")) {
        if (argc >= 2) {
            uint64_t addr;
            sscanf(argv[1], "%lx", &addr);
            if (do_breakpoint(debugger, addr) == 0) {
                fprintf(stderr, "failed to add breakpoint at 0x%lx\n", addr);
            }
        } else {
            fprintf(stderr, "usage: breakpoint address\n");
        }
    } else if (is_prefix(argv[0], "register")) {
        if (argc >= 2 && is_prefix(argv[1], "dump")) {
            dump_registers(debugger);
        } else if (argc >= 3 && is_prefix(argv[1], "read")) {
            uint64_t reg;
            uint32_t status = get_register(debugger, argv[2], &reg);
            if (status == 0) {
                fprintf(stderr, "register %s not found\n", argv[2]);
            } else {
                fprintf(stdout, "%s: 0x%lx\n", argv[2], reg);
            }
        } else if (argc >= 4 && is_prefix(argv[1], "write")) {
            uint64_t value;
            sscanf(argv[3], "%lx", &value);
            uint32_t status = set_register(debugger, argv[2], value);
            if (status == 0) {
                fprintf(stderr, "register %s not found\n", argv[2]);
            }
        } else {
            fprintf(stderr, "usage: register (dump|read|write) [address] [value]\n");
        }
    } else if (is_prefix(argv[0], "memory")) {
        if (argc >= 3 && is_prefix(argv[1], "read")) {
            uint64_t addr;
            sscanf(argv[2], "%lx", &addr);
            uint64_t mem;
            get_memory(debugger, addr, &mem);
            fprintf(stdout, "memory: 0x%lx\n", mem);
        } else if (argc >= 4 && is_prefix(argv[1], "write")) {
            uint64_t addr, value;
            sscanf(argv[2], "%lx", &addr);
            sscanf(argv[3], "%lx", &value);
            set_memory(debugger, addr, value);
        } else {
            fprintf(stderr, "usage: memory (read|write) [address] [value]\n");
        }
    } else if (is_prefix(argv[0], "step")) {
        do_step(debugger);
    } else if (is_prefix(argv[0], "continue")) {
        do_continue(debugger);
    } else if (is_prefix(argv[0], "asm")) {
        read_asm(debugger);
    } else {
        fprintf(stderr, "command not found\n");
    }
    return 1;
}

// signal
siginfo_t get_signal_info(struct Debugger *debugger) {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, debugger->pid, NULL, &info);
    return info;
}

void wait_for_signal(struct Debugger *debugger) {
    int32_t wait_status;
    waitpid(debugger->pid, &wait_status, 0);

    siginfo_t info = get_signal_info(debugger);

    switch (info.si_signo) {
    case SIGTRAP:
        handle_sigtrap(debugger, info);
        break;
    case SIGSEGV:
        fprintf(stdout, "signal SIGSEGV with code %d\n", info.si_code);
        break;
    default:
        fprintf(stdout, "got signal %s\n", strsignal(info.si_signo));
    }
}

void handle_sigtrap(struct Debugger *debugger, siginfo_t info) {
    switch (info.si_code) {
    // hit breakpoint
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        if (debugger->breakpoint_callback) {
            enable_breakpoint(debugger, debugger->breakpoint_callback);
            debugger->breakpoint_callback = NULL;
        }

        uint64_t pc;
        get_register(debugger, "rip", &pc);
        struct Breakpoint *breakpoint = is_breakpoint_exit(debugger, pc - 1);
        if (breakpoint) {
            fprintf(stdout, "hit breakpoint at 0x%lx\n", pc - 1);
            disable_breakpoint(debugger, breakpoint);
            set_register(debugger, "rip", pc - 1);
            debugger->breakpoint_callback = breakpoint;
        } else {
            fprintf(stdout, "hit unexpected breakpoint\n");
        }
        break;
    }
    // single step
    case TRAP_TRACE:
    {
        if (debugger->breakpoint_callback) {
            enable_breakpoint(debugger, debugger->breakpoint_callback);
            debugger->breakpoint_callback = NULL;
        }
        break;
    }
    // kill, sigsend, raise
    case SI_USER:
        break;
    default:
        fprintf(stdout, "unknown signal SIGTRAP with code %d\n", info.si_code);
    }
}

// quit
void do_quit(struct Debugger *debugger) {
    ptrace(PTRACE_DETACH, debugger->pid, NULL, NULL);
}

// step

void do_step(struct Debugger *debugger) {
    ptrace(PTRACE_SINGLESTEP, debugger->pid, NULL, NULL);
    wait_for_signal(debugger);
}

// continue
void do_continue(struct Debugger *debugger) {
    ptrace(PTRACE_CONT, debugger->pid, NULL, NULL);
    wait_for_signal(debugger);
}

// register
// -1: not found, n: index
int32_t find_register_index(char *name) {
    for (uint32_t i = 0; i < num_regs; i++) {
        if (strcmp(reg_list[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

// 0: not found, 1: sucessed
uint32_t get_register(struct Debugger *debugger, char *name, uint64_t *value) {
    struct user_regs_struct regs;
    uint32_t index = find_register_index(name);
    if (index == -1) {
        return 0;
    }
    if (value != NULL) {
        ptrace(PTRACE_GETREGS, debugger->pid, NULL, &regs);
        *value = *(uint64_t *)((uint64_t *)&regs + index);
    }
    return 1;
}

// 0: not found, 1: sucessed
uint32_t set_register(struct Debugger *debugger, char *name, uint64_t value) {
    struct user_regs_struct regs;
    uint32_t index = find_register_index(name);
    if (index == -1) {
        return 0;
    }
    ptrace(PTRACE_GETREGS, debugger->pid, NULL, &regs);
    *(uint64_t *)((uint64_t *)&regs + index) = value;
    ptrace(PTRACE_SETREGS, debugger->pid, NULL, &regs);
    return 1;
}

void dump_registers(struct Debugger *debugger) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, debugger->pid, NULL, &regs);
    fprintf(stdout, "-------------------------[Register]-------------------------\n");
    for (uint32_t i = 0; i < num_regs; i++) {
        fprintf(stdout, "%-10s: 0x%lx\n", reg_list[i].name, *(uint64_t *)((uint64_t *)&regs + i));
    }
}

// memory
void get_memory(struct Debugger *debugger, uint64_t addr, uint64_t *value) {
    if (value != NULL) {
        *value = (uint64_t)ptrace(PTRACE_PEEKDATA, debugger->pid, addr, NULL);
    }
}

void set_memory(struct Debugger *debugger, uint64_t addr, uint64_t value) {
    ptrace(PTRACE_POKEDATA, debugger->pid, addr, value);
}

// breakpoint
// 0: different, 1: same
uint32_t breakpoint_cmp(void *a, void *b) {
    return ((struct Breakpoint *)a)->addr == ((struct Breakpoint *)b)->addr;
}

// null: not found, not null: address
struct Breakpoint *is_breakpoint_exit(struct Debugger *debugger, uint64_t addr) {
    struct Breakpoint breakpoint;
    breakpoint.addr = addr; 
    struct ListEntry *entry = check_list(&(debugger->breakpoints_head), &breakpoint, breakpoint_cmp);
    if (entry) {
        return (struct Breakpoint *)entry->data;
    } else {
        return NULL;
    }
}

// 0: failed, 1: sucessed
uint32_t add_breakpoint(struct Debugger *debugger, uint64_t addr) {
    if (!is_breakpoint_exit(debugger, addr)) {
        struct Breakpoint *new_breakpoint = malloc(sizeof(struct Breakpoint));
        new_breakpoint->addr = addr;
        new_breakpoint->is_enable = 0;
        insert_list(&(debugger->breakpoints_head), (void *)new_breakpoint);
        return 1;
    }
    return 0;
}

// 0: failed, 1: sucessed
uint32_t enable_breakpoint(struct Debugger *debugger, struct Breakpoint *breakpoint) {
    if (breakpoint && breakpoint->is_enable == 0) {
        uint64_t instruction;
        get_memory(debugger, breakpoint->addr, &instruction);
        breakpoint->save_instruction = 0xff & instruction;
        set_memory(debugger, breakpoint->addr, (~0xff & instruction) | INT3);
        breakpoint->is_enable = 1;
        return 1;
    }
    return 0;
}

// 0: failed, 1: sucessed
uint32_t disable_breakpoint(struct Debugger *debugger, struct Breakpoint *breakpoint) {
    if (breakpoint && breakpoint->is_enable == 1) {
        uint64_t instruction;
        get_memory(debugger, breakpoint->addr, &instruction);
        set_memory(debugger, breakpoint->addr, (~0xff & instruction) | breakpoint->save_instruction);
        breakpoint->is_enable = 0;
        return 1;
    }
    return 0;
}

// 0: failed, 1: sucessed
uint32_t enable_breakpoint_by_addr(struct Debugger *debugger, uint64_t addr) {
    struct Breakpoint *breakpoint = is_breakpoint_exit(debugger, addr);
    return enable_breakpoint(debugger, breakpoint);
}

// 0: failed, 1: sucessed
uint32_t disable_breakpoint_by_addr(struct Debugger *debugger, uint64_t addr) {
    struct Breakpoint *breakpoint = is_breakpoint_exit(debugger, addr);
    return disable_breakpoint(debugger, breakpoint);
}

// 0: failed, 1: sucessed
uint32_t do_breakpoint(struct Debugger *debugger, uint64_t addr) {
    if (add_breakpoint(debugger, addr) == 0) {
        return 0;
    }
    if (enable_breakpoint_by_addr(debugger, addr) == 0) {
        return 0;
    }
}

// asm
void read_asm(struct Debugger *debugger) {
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
        fprintf(stderr, "cs_open(%d, %d, 0x%p) failed\n", CS_ARCH_X86, CS_MODE_64, &handle);
        return;
    }

    uint8_t *code;
    cs_insn *insn;
    const uint64_t ins_size = 0x20;
    uint64_t size = ins_size;
    uint64_t addr;

    get_register(debugger, "rip", &addr);
    code = calloc(1, ins_size);
    for (uint32_t i = 0; i < 4; i++) {
        get_memory(debugger, addr + 8 * i, (uint64_t *)code + i);
    }

    for (uint32_t i = 0; i < ins_size; i++) {
        struct Breakpoint *breakpoint = is_breakpoint_exit(debugger, addr + i);
        if (breakpoint && breakpoint->is_enable == 1) {
            *((uint8_t *)code + i) = (uint8_t)(breakpoint->save_instruction);
        }
    }

    fprintf(stdout, "-------------------------[Assembly]-------------------------\n");
    insn = cs_malloc(handle);
    while (cs_disasm_iter(handle, (const uint8_t **)&code, &size, &addr, insn)) {
        if (size + insn->size == 0x20) {
            fprintf(stdout, RED "0x%08lx:\t%s\t%s <- rip\n" BLACK, insn->address, insn->mnemonic, insn->op_str);
        } else {
            fprintf(stdout, "0x%08lx:\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);  
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
}