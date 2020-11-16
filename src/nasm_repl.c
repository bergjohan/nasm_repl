#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "linenoise.h"

extern void run_child(void);

#define NOP 0x90

#define STACK_SIZE 128

#define COLOR_RESET "\033[m"
#define COLOR_STACK_DIFF "\033[1;31m"
#define COLOR_RSP "\033[1;34m"

// Must be a power of two
#define MAP_CAPACITY 32

typedef char command_name[16];

enum eflags {
    EFLAGS_CF = 0x00000001,
    EFLAGS_PF = 0x00000004,
    EFLAGS_AF = 0x00000010,
    EFLAGS_ZF = 0x00000040,
    EFLAGS_SF = 0x00000080,
    EFLAGS_TF = 0x00000100,
    EFLAGS_IF = 0x00000200,
    EFLAGS_DF = 0x00000400,
    EFLAGS_OF = 0x00000800,
    EFLAGS_IOPL = 0x00003000,
    EFLAGS_NT = 0x00004000,
    EFLAGS_RF = 0x00010000,
    EFLAGS_VM = 0x00020000,
    EFLAGS_AC = 0x00040000,
    EFLAGS_VIF = 0x00080000,
    EFLAGS_VIP = 0x00100000,
    EFLAGS_ID = 0x00200000
};

enum command_type {
    COMMAND_UNKNOWN,
    COMMAND_STACK,
    COMMAND_REGS,
    COMMAND_RAX,
    COMMAND_RBX,
    COMMAND_RCX,
    COMMAND_RDX,
    COMMAND_RSI,
    COMMAND_RDI,
    COMMAND_RBP,
    COMMAND_RSP,
    COMMAND_R8,
    COMMAND_R9,
    COMMAND_R10,
    COMMAND_R11,
    COMMAND_R12,
    COMMAND_R13,
    COMMAND_R14,
    COMMAND_R15,
    COMMAND_RIP,
    COMMAND_EFLAGS,
    COMMAND_CS,
    COMMAND_SS,
    COMMAND_DS,
    COMMAND_ES,
    COMMAND_FS,
    COMMAND_GS
};

struct state {
    unsigned char prev_stack[STACK_SIZE];
    unsigned char stack[STACK_SIZE];
    struct user_regs_struct prev_regs;
    struct user_regs_struct regs;
    uint64_t rip;
    uint64_t frame_pointer;
};

struct map {
    command_name name[MAP_CAPACITY];
    enum command_type type[MAP_CAPACITY];
};

static struct map map;

void die(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "fatal: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

uint64_t to_u64(unsigned char *data) {
    return (uint64_t)data[0] | (uint64_t)data[1] << 8 |
           (uint64_t)data[2] << 16 | (uint64_t)data[3] << 24 |
           (uint64_t)data[4] << 32 | (uint64_t)data[5] << 40 |
           (uint64_t)data[6] << 48 | (uint64_t)data[7] << 56;
}

char *skip_whitespace(char *str) {
    while (isspace(*str)) {
        str++;
    }
    return str;
}

char *skip_until(char *str, char c) {
    while (*str) {
        if (*str == c) {
            break;
        }
        str++;
    }
    return str;
}

int find_nasm(void) {
    char *tmp = getenv("PATH");
    if (!tmp) {
        die("getenv() failed\n");
    }

    // Duplicate string since it will be destroyed by strtok
    char *value = strdup(tmp);
    if (!value) {
        die("strdup() failed\n");
    }

    char *token = strtok(value, ":");
    while (token) {
        char *path;
        if (asprintf(&path, "%s/nasm", token) == -1) {
            die("asprintf() failed\n");
        }

        struct stat sb;
        if (stat(path, &sb) != -1 && !S_ISDIR(sb.st_mode)) {
            free(path);
            free(value);
            return 0;
        }

        free(path);
        token = strtok(NULL, ":");
    }

    free(value);
    return -1;
}

void print_stack(uint64_t frame_pointer, uint64_t rsp,
                 unsigned char *prev_stack, unsigned char *stack, size_t size) {
    uint64_t address = frame_pointer - size;
    unsigned char ascii[17] = {0};

    printf("%lx  ", address);
    for (size_t i = 0; i < size; i++, address++) {
        if (address == rsp) {
            printf(COLOR_RSP "%02x " COLOR_RESET, stack[i]);
        } else if (prev_stack[i] != stack[i]) {
            printf(COLOR_STACK_DIFF "%02x " COLOR_RESET, stack[i]);
        } else {
            printf("%02x ", stack[i]);
        }
        if (isprint(stack[i])) {
            ascii[i % 16] = stack[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0) {
            printf(" ");
        }
        if ((i + 1) % 16 == 0) {
            printf("|%s|\n", ascii);
            if ((i + 1) != size) {
                printf("%lx  ", address);
            }
        } else if ((i + 1) == size) {
            ascii[(i + 1) % 16] = '\0';
            for (size_t j = (i + 1) % 16; j < 16; j++) {
                if ((j + 1) % 8 == 0) {
                    printf(" ");
                }
                printf("   ");
            }
            printf("|%s|\n", ascii);
        }
    }
}

void print_eflags(uint64_t eflags) {
    printf("%-15s0x%-18lx%s", "eflags", eflags, "[ ");
    if (eflags & EFLAGS_CF) {
        printf("CF ");
    }
    if (eflags & EFLAGS_PF) {
        printf("PF ");
    }
    if (eflags & EFLAGS_AF) {
        printf("AF ");
    }
    if (eflags & EFLAGS_ZF) {
        printf("ZF ");
    }
    if (eflags & EFLAGS_SF) {
        printf("SF ");
    }
    if (eflags & EFLAGS_TF) {
        printf("TF ");
    }
    if (eflags & EFLAGS_IF) {
        printf("IF ");
    }
    if (eflags & EFLAGS_DF) {
        printf("DF ");
    }
    if (eflags & EFLAGS_OF) {
        printf("OF ");
    }
    if (eflags & EFLAGS_IOPL) {
        printf("IOPL ");
    }
    if (eflags & EFLAGS_NT) {
        printf("NT ");
    }
    if (eflags & EFLAGS_RF) {
        printf("RF ");
    }
    if (eflags & EFLAGS_VM) {
        printf("VM ");
    }
    if (eflags & EFLAGS_AC) {
        printf("AC ");
    }
    if (eflags & EFLAGS_VIF) {
        printf("VIF ");
    }
    if (eflags & EFLAGS_VIP) {
        printf("VIP ");
    }
    if (eflags & EFLAGS_ID) {
        printf("ID ");
    }
    printf("]\n");
}

void print_regs(struct user_regs_struct *regs) {
    printf("%-15s0x%-18llx%lld\n", "rax", regs->rax, regs->rax);
    printf("%-15s0x%-18llx%lld\n", "rbx", regs->rbx, regs->rbx);
    printf("%-15s0x%-18llx%lld\n", "rcx", regs->rcx, regs->rcx);
    printf("%-15s0x%-18llx%lld\n", "rdx", regs->rdx, regs->rdx);
    printf("%-15s0x%-18llx%lld\n", "rsi", regs->rsi, regs->rsi);
    printf("%-15s0x%-18llx%lld\n", "rdi", regs->rdi, regs->rdi);
    printf("%-15s0x%-18llx0x%llx\n", "rbp", regs->rbp, regs->rbp);
    printf("%-15s0x%-18llx0x%llx\n", "rsp", regs->rsp, regs->rsp);
    printf("%-15s0x%-18llx%lld\n", "r8", regs->r8, regs->r8);
    printf("%-15s0x%-18llx%lld\n", "r9", regs->r9, regs->r9);
    printf("%-15s0x%-18llx%lld\n", "r10", regs->r10, regs->r10);
    printf("%-15s0x%-18llx%lld\n", "r11", regs->r11, regs->r11);
    printf("%-15s0x%-18llx%lld\n", "r12", regs->r12, regs->r12);
    printf("%-15s0x%-18llx%lld\n", "r13", regs->r13, regs->r13);
    printf("%-15s0x%-18llx%lld\n", "r14", regs->r14, regs->r14);
    printf("%-15s0x%-18llx%lld\n", "r15", regs->r15, regs->r15);
    printf("%-15s0x%-18llx0x%llx\n", "rip", regs->rip, regs->rip);
    print_eflags(regs->eflags);
    printf("%-15s0x%-18llx%lld\n", "cs", regs->cs, regs->cs);
    printf("%-15s0x%-18llx%lld\n", "ss", regs->ss, regs->ss);
    printf("%-15s0x%-18llx%lld\n", "ds", regs->ds, regs->ds);
    printf("%-15s0x%-18llx%lld\n", "es", regs->es, regs->es);
    printf("%-15s0x%-18llx%lld\n", "fs", regs->fs, regs->fs);
    printf("%-15s0x%-18llx%lld\n", "gs", regs->gs, regs->gs);
}

void print_changed_regs(struct user_regs_struct *prev_regs,
                        struct user_regs_struct *regs) {
    if (prev_regs->rax != regs->rax) {
        printf("%-15s0x%-18llx%lld\n", "rax", regs->rax, regs->rax);
    }
    if (prev_regs->rbx != regs->rbx) {
        printf("%-15s0x%-18llx%lld\n", "rbx", regs->rbx, regs->rbx);
    }
    if (prev_regs->rcx != regs->rcx) {
        printf("%-15s0x%-18llx%lld\n", "rcx", regs->rcx, regs->rcx);
    }
    if (prev_regs->rdx != regs->rdx) {
        printf("%-15s0x%-18llx%lld\n", "rdx", regs->rdx, regs->rdx);
    }
    if (prev_regs->rsi != regs->rsi) {
        printf("%-15s0x%-18llx%lld\n", "rsi", regs->rsi, regs->rsi);
    }
    if (prev_regs->rdi != regs->rdi) {
        printf("%-15s0x%-18llx%lld\n", "rdi", regs->rdi, regs->rdi);
    }
    if (prev_regs->rbp != regs->rbp) {
        printf("%-15s0x%-18llx0x%llx\n", "rbp", regs->rbp, regs->rbp);
    }
    if (prev_regs->rsp != regs->rsp) {
        printf("%-15s0x%-18llx0x%llx\n", "rsp", regs->rsp, regs->rsp);
    }
    if (prev_regs->r8 != regs->r8) {
        printf("%-15s0x%-18llx%lld\n", "r8", regs->r8, regs->r8);
    }
    if (prev_regs->r9 != regs->r9) {
        printf("%-15s0x%-18llx%lld\n", "r9", regs->r9, regs->r9);
    }
    if (prev_regs->r10 != regs->r10) {
        printf("%-15s0x%-18llx%lld\n", "r10", regs->r10, regs->r10);
    }
    if (prev_regs->r11 != regs->r11) {
        printf("%-15s0x%-18llx%lld\n", "r11", regs->r11, regs->r11);
    }
    if (prev_regs->r12 != regs->r12) {
        printf("%-15s0x%-18llx%lld\n", "r12", regs->r12, regs->r12);
    }
    if (prev_regs->r13 != regs->r13) {
        printf("%-15s0x%-18llx%lld\n", "r13", regs->r13, regs->r13);
    }
    if (prev_regs->r14 != regs->r14) {
        printf("%-15s0x%-18llx%lld\n", "r14", regs->r14, regs->r14);
    }
    if (prev_regs->r15 != regs->r15) {
        printf("%-15s0x%-18llx%lld\n", "r15", regs->r15, regs->r15);
    }
    if (prev_regs->eflags != regs->eflags) {
        print_eflags(regs->eflags);
    }
    if (prev_regs->cs != regs->cs) {
        printf("%-15s0x%-18llx%lld\n", "cs", regs->cs, regs->cs);
    }
    if (prev_regs->ss != regs->ss) {
        printf("%-15s0x%-18llx%lld\n", "ss", regs->ss, regs->ss);
    }
    if (prev_regs->ds != regs->ds) {
        printf("%-15s0x%-18llx%lld\n", "ds", regs->ds, regs->ds);
    }
    if (prev_regs->es != regs->es) {
        printf("%-15s0x%-18llx%lld\n", "es", regs->es, regs->es);
    }
    if (prev_regs->fs != regs->fs) {
        printf("%-15s0x%-18llx%lld\n", "fs", regs->fs, regs->fs);
    }
    if (prev_regs->gs != regs->gs) {
        printf("%-15s0x%-18llx%lld\n", "gs", regs->gs, regs->gs);
    }
}

uint32_t fnv1a(char *str) {
    unsigned char *s = (unsigned char *)str;
    uint32_t hash = 0;

    while (*s) {
        hash ^= (uint32_t)*s++;
        hash *= 0x01000193;
    }
    return hash;
}

void add_command(char *name, enum command_type type) {
    uint32_t i = fnv1a(name);

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (map.name[i][0] == '\0') {
            strcpy(map.name[i], name);
            map.type[i] = type;
            return;
        }
        i++;
    }
}

enum command_type find_command(char *name) {
    uint32_t i = fnv1a(name);

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strcmp(name, map.name[i]) == 0) {
            return map.type[i];
        } else if (map.name[i][0] == '\0') {
            return COMMAND_UNKNOWN;
        }
        i++;
    }
}

void init_commands(void) {
    add_command("stack", COMMAND_STACK);
    add_command("regs", COMMAND_REGS);
    add_command("rax", COMMAND_RAX);
    add_command("rbx", COMMAND_RBX);
    add_command("rcx", COMMAND_RCX);
    add_command("rdx", COMMAND_RDX);
    add_command("rsi", COMMAND_RSI);
    add_command("rdi", COMMAND_RDI);
    add_command("rbp", COMMAND_RBP);
    add_command("rsp", COMMAND_RSP);
    add_command("r8", COMMAND_R8);
    add_command("r9", COMMAND_R9);
    add_command("r10", COMMAND_R10);
    add_command("r11", COMMAND_R11);
    add_command("r12", COMMAND_R12);
    add_command("r13", COMMAND_R13);
    add_command("r14", COMMAND_R14);
    add_command("r15", COMMAND_R15);
    add_command("rip", COMMAND_RIP);
    add_command("eflags", COMMAND_EFLAGS);
    add_command("cs", COMMAND_CS);
    add_command("ss", COMMAND_SS);
    add_command("ds", COMMAND_DS);
    add_command("es", COMMAND_ES);
    add_command("fs", COMMAND_FS);
    add_command("gs", COMMAND_GS);
}

void read_data(pid_t pid, uint64_t frame_pointer, unsigned char *buf,
               size_t size) {
    struct iovec local[1];
    local[0].iov_base = buf;
    local[0].iov_len = size;

    struct iovec remote[1];
    remote[0].iov_base = (void *)(frame_pointer - size);
    remote[0].iov_len = size;

    if (process_vm_readv(pid, local, 1, remote, 1, 0) == -1) {
        die("process_vm_readv() failed\n");
    }
}

void write_data(pid_t pid, uint64_t address, uint64_t data) {
    if (ptrace(PTRACE_POKEDATA, pid, address, data) == -1) {
        die("ptrace() failed\n");
    }
}

void read_registers(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        die("ptrace() failed\n");
    }
}

void write_registers(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        die("ptrace() failed\n");
    }
}

void cont(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        die("ptrace() failed\n");
    }
    if (waitpid(pid, NULL, 0) == -1) {
        die("waitpid() failed\n");
    }
}

void execute_instruction(pid_t pid) {
    cont(pid);

    siginfo_t info;
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &info) == -1) {
        die("ptrace() failed\n");
    }
    if (info.si_signo == SIGSEGV) {
        fprintf(stderr, "Segmentation fault\n");
    }
}

int write_all(int fd, const void *buf) {
    size_t offset = 0;
    size_t totalsize = strlen(buf);
    const char *ptr = buf;

    while (offset < totalsize) {
        ssize_t ret = write(fd, ptr + offset, totalsize - offset);
        if (ret == -1) {
            return -1;
        }
        offset += (size_t)ret;
    }

    return 0;
}

int write_assembly(int fd, char *line) {
    char *buf;
    if (asprintf(&buf, "BITS 64\n%s\n", line) == -1) {
        close(fd);
        return -1;
    }

    if (write_all(fd, buf) == -1) {
        free(buf);
        close(fd);
        return -1;
    }

    free(buf);
    close(fd);
    return 0;
}

int run_nasm(char *infile, char *outfile) {
    char command[64];
    sprintf(command, "nasm -f bin -o %s %s", outfile, infile);
    if (system(command) != 0) {
        unlink(infile);
        return -1;
    }

    unlink(infile);
    return 0;
}

size_t read_instruction(char *outfile, unsigned char *data, size_t size) {
    FILE *fp = fopen(outfile, "r");
    if (!fp) {
        fclose(fp);
        unlink(outfile);
        die("fopen() failed\n");
    }

    size_t ret = fread(data, 1, size, fp);
    if (ferror(fp)) {
        fclose(fp);
        unlink(outfile);
        die("fread() failed\n");
    }

    fclose(fp);
    unlink(outfile);
    return ret;
}

size_t assemble(char *line, unsigned char *data, size_t size) {
    char infile[] = "nasmXXXXXX";
    int fd = mkstemp(infile);
    if (fd == -1) {
        die("mkstemp() failed\n");
    }

    if (write_assembly(fd, line) == -1) {
        unlink(infile);
        die("write_assembly() failed\n");
    }

    char outfile[16];
    sprintf(outfile, "%s.out", infile);

    if (run_nasm(infile, outfile) != 0) {
        return 0;
    }

    return read_instruction(outfile, data, size);
}

void handle_asm_command(pid_t pid, char *line, struct state *state) {
    uint64_t rbx = 0;
    unsigned char data[16];
    size_t size;

    if (strncmp(line, "call ", 5) == 0) {
        char *symbol = line + 5;
        symbol = skip_whitespace(symbol);

        // Clear any existing error
        dlerror();

        uint64_t address = (uint64_t)dlsym(RTLD_NEXT, symbol);
        char *error = dlerror();
        if (error != NULL) {
            fprintf(stderr, "%s\n", error);
            return;
        }

        // Save rbx
        rbx = state->prev_regs.rbx;

        // Load rbx with address of symbol
        state->prev_regs.rbx = address;
        write_registers(pid, &state->prev_regs);

        size = assemble("call rbx", data, sizeof(data));
        if (size == 0) {
            return;
        }
    } else {
        size = assemble(line, data, sizeof(data));
        if (size == 0) {
            return;
        }
    }

    // Pad with nops
    memset(data + size, NOP, sizeof(data) - size);

    // Write instruction
    write_data(pid, state->rip, to_u64(data));
    write_data(pid, state->rip + 8, to_u64(&data[8]));

    execute_instruction(pid);

    read_data(pid, state->frame_pointer, state->stack, sizeof(state->stack));
    read_registers(pid, &state->regs);

    // Restore rbx
    if (rbx != 0 && state->prev_regs.rbx == state->regs.rbx) {
        state->prev_regs.rbx = rbx;
        state->regs.rbx = rbx;
        write_registers(pid, &state->regs);
    }

    if (memcmp(state->prev_stack, state->stack, sizeof(state->stack)) != 0) {
        print_stack(state->frame_pointer, state->regs.rsp, state->prev_stack,
                    state->stack, sizeof(state->stack));
    }

    if (memcmp(&state->prev_regs, &state->regs, sizeof(state->regs)) != 0) {
        print_changed_regs(&state->prev_regs, &state->regs);
    }
}

void handle_command(pid_t pid, char *line, struct state *state) {
    read_data(pid, state->frame_pointer, state->prev_stack,
              sizeof(state->prev_stack));
    read_registers(pid, &state->prev_regs);

    // Trim leading whitespace
    line = skip_whitespace(line);
    char *start = line;
    // Move to end of token
    line = skip_until(line, ' ');
    char *end = line;
    // Trim trailing whitespace
    line = skip_whitespace(line);
    enum command_type type = COMMAND_UNKNOWN;
    // Don't allow trailing tokens
    if (*line == '\0') {
        *end = '\0';
        type = find_command(start);
    }

    switch (type) {
    case COMMAND_STACK:
        print_stack(state->frame_pointer, state->prev_regs.rsp,
                    state->prev_stack, state->stack, sizeof(state->stack));
        break;
    case COMMAND_REGS:
        print_regs(&state->prev_regs);
        break;
    case COMMAND_RAX:
        printf("%-15s0x%-18llx%lld\n", "rax", state->regs.rax, state->regs.rax);
        break;
    case COMMAND_RBX:
        printf("%-15s0x%-18llx%lld\n", "rbx", state->regs.rbx, state->regs.rbx);
        break;
    case COMMAND_RCX:
        printf("%-15s0x%-18llx%lld\n", "rcx", state->regs.rcx, state->regs.rcx);
        break;
    case COMMAND_RDX:
        printf("%-15s0x%-18llx%lld\n", "rdx", state->regs.rdx, state->regs.rdx);
        break;
    case COMMAND_RSI:
        printf("%-15s0x%-18llx%lld\n", "rsi", state->regs.rsi, state->regs.rsi);
        break;
    case COMMAND_RDI:
        printf("%-15s0x%-18llx%lld\n", "rdi", state->regs.rdi, state->regs.rdi);
        break;
    case COMMAND_RBP:
        printf("%-15s0x%-18llx0x%llx\n", "rbp", state->regs.rbp,
               state->regs.rbp);
        break;
    case COMMAND_RSP:
        printf("%-15s0x%-18llx0x%llx\n", "rsp", state->regs.rsp,
               state->regs.rsp);
        break;
    case COMMAND_R8:
        printf("%-15s0x%-18llx%lld\n", "r8", state->regs.r8, state->regs.r8);
        break;
    case COMMAND_R9:
        printf("%-15s0x%-18llx%lld\n", "r9", state->regs.r9, state->regs.r9);
        break;
    case COMMAND_R10:
        printf("%-15s0x%-18llx%lld\n", "r10", state->regs.r10, state->regs.r10);
        break;
    case COMMAND_R11:
        printf("%-15s0x%-18llx%lld\n", "r11", state->regs.r11, state->regs.r11);
        break;
    case COMMAND_R12:
        printf("%-15s0x%-18llx%lld\n", "r12", state->regs.r12, state->regs.r12);
        break;
    case COMMAND_R13:
        printf("%-15s0x%-18llx%lld\n", "r13", state->regs.r13, state->regs.r13);
        break;
    case COMMAND_R14:
        printf("%-15s0x%-18llx%lld\n", "r14", state->regs.r14, state->regs.r14);
        break;
    case COMMAND_R15:
        printf("%-15s0x%-18llx%lld\n", "r15", state->regs.r15, state->regs.r15);
        break;
    case COMMAND_RIP:
        printf("%-15s0x%-18llx0x%llx\n", "rip", state->regs.rip,
               state->regs.rip);
        break;
    case COMMAND_EFLAGS:
        print_eflags(state->regs.eflags);
        break;
    case COMMAND_CS:
        printf("%-15s0x%-18llx%lld\n", "cs", state->regs.cs, state->regs.cs);
        break;
    case COMMAND_SS:
        printf("%-15s0x%-18llx%lld\n", "ss", state->regs.ss, state->regs.ss);
        break;
    case COMMAND_DS:
        printf("%-15s0x%-18llx%lld\n", "ds", state->regs.ds, state->regs.ds);
        break;
    case COMMAND_ES:
        printf("%-15s0x%-18llx%lld\n", "es", state->regs.es, state->regs.es);
        break;
    case COMMAND_FS:
        printf("%-15s0x%-18llx%lld\n", "fs", state->regs.fs, state->regs.fs);
        break;
    case COMMAND_GS:
        printf("%-15s0x%-18llx%lld\n", "gs", state->regs.gs, state->regs.gs);
        break;
    default:
        handle_asm_command(pid, start, state);
        break;
    }
}

void init_state(pid_t pid, struct state *state) {
    // Since we'll be using memcmp
    memset(&state->prev_regs, 0, sizeof(state->prev_regs));
    memset(&state->regs, 0, sizeof(state->regs));

    read_registers(pid, &state->regs);
    state->rip = state->regs.rip;
    state->frame_pointer = state->regs.rsp;

    read_data(pid, state->frame_pointer, state->stack, sizeof(state->stack));
}

void run(pid_t pid) {
    if (waitpid(pid, NULL, 0) == -1) {
        die("waitpid() failed\n");
    }

    struct state state;
    init_state(pid, &state);

    init_commands();

    char *line;
    while ((line = linenoise("> ")) != NULL) {
        linenoiseHistoryAdd(line);
        handle_command(pid, line, &state);
        linenoiseFree(line);
    }

    // Move rip to ret instruction (16 nops + one jmp)
    state.regs.rip += 16 + 2;
    // Restore stack pointer
    state.regs.rsp = state.frame_pointer;
    write_registers(pid, &state.regs);
    cont(pid);
}

int main(void) {
    if (find_nasm() != 0) {
        die("No nasm installation was found.\n");
    }

    pid_t cpid = fork();
    if (cpid == -1) {
        die("fork() failed\n");
    }

    if (cpid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        run_child();
    } else {
        run(cpid);
    }
}
