#define _GNU_SOURCE
#include <ctype.h>
#include <dlfcn.h>
#include <elf.h>
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

#include "lexer.h"
#include "linenoise.h"

extern void run_child(void);

#define NOP 0x90

#define STACK_SIZE 128

#define COLOR_RESET "\033[m"
#define COLOR_STACK_DIFF "\033[1;31m"
#define COLOR_RSP "\033[1;34m"

typedef struct user_regs_struct user_regs_struct;

typedef enum Eflags {
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
} Eflags;

typedef struct State {
    unsigned char prev_stack[STACK_SIZE];
    unsigned char stack[STACK_SIZE];
    user_regs_struct prev_regs;
    user_regs_struct regs;
    uint64_t rip;
    uint64_t frame_pointer;
} State;

void die(const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "fatal: ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    exit(1);
}

uint64_t to_u64(const unsigned char *data) {
    uint64_t ret;
    memcpy(&ret, data, sizeof(ret));
    return ret;
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
                 const unsigned char *prev_stack, const unsigned char *stack,
                 size_t size) {
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

void print_reg(const char *name, uint64_t reg) {
    printf("%-15s0x%-18lx%ld\n", name, reg, reg);
}

void print_reg_addr(const char *name, uint64_t reg) {
    printf("%-15s0x%-18lx0x%lx\n", name, reg, reg);
}

void print_regs(const user_regs_struct *regs) {
    print_reg("rax", regs->rax);
    print_reg("rbx", regs->rbx);
    print_reg("rcx", regs->rcx);
    print_reg("rdx", regs->rdx);
    print_reg("rsi", regs->rsi);
    print_reg("rdi", regs->rdi);
    print_reg_addr("rbp", regs->rbp);
    print_reg_addr("rsp", regs->rsp);
    print_reg("r8", regs->r8);
    print_reg("r9", regs->r9);
    print_reg("r10", regs->r10);
    print_reg("r11", regs->r11);
    print_reg("r12", regs->r12);
    print_reg("r13", regs->r13);
    print_reg("r14", regs->r14);
    print_reg("r15", regs->r15);
    print_reg_addr("rip", regs->rip);
    print_eflags(regs->eflags);
    print_reg("cs", regs->cs);
    print_reg("ss", regs->ss);
    print_reg("ds", regs->ds);
    print_reg("es", regs->es);
    print_reg("fs", regs->fs);
    print_reg("gs", regs->gs);
}

void print_changed_regs(const user_regs_struct *prev_regs,
                        const user_regs_struct *regs) {
    if (prev_regs->rax != regs->rax) {
        print_reg("rax", regs->rax);
    }
    if (prev_regs->rbx != regs->rbx) {
        print_reg("rbx", regs->rbx);
    }
    if (prev_regs->rcx != regs->rcx) {
        print_reg("rcx", regs->rcx);
    }
    if (prev_regs->rdx != regs->rdx) {
        print_reg("rdx", regs->rdx);
    }
    if (prev_regs->rsi != regs->rsi) {
        print_reg("rsi", regs->rsi);
    }
    if (prev_regs->rdi != regs->rdi) {
        print_reg("rdi", regs->rdi);
    }
    if (prev_regs->rbp != regs->rbp) {
        print_reg_addr("rbp", regs->rbp);
    }
    if (prev_regs->rsp != regs->rsp) {
        print_reg_addr("rsp", regs->rsp);
    }
    if (prev_regs->r8 != regs->r8) {
        print_reg("r8", regs->r8);
    }
    if (prev_regs->r9 != regs->r9) {
        print_reg("r9", regs->r9);
    }
    if (prev_regs->r10 != regs->r10) {
        print_reg("r10", regs->r10);
    }
    if (prev_regs->r11 != regs->r11) {
        print_reg("r11", regs->r11);
    }
    if (prev_regs->r12 != regs->r12) {
        print_reg("r12", regs->r12);
    }
    if (prev_regs->r13 != regs->r13) {
        print_reg("r13", regs->r13);
    }
    if (prev_regs->r14 != regs->r14) {
        print_reg("r14", regs->r14);
    }
    if (prev_regs->r15 != regs->r15) {
        print_reg("r15", regs->r15);
    }
    if (prev_regs->eflags != regs->eflags) {
        print_eflags(regs->eflags);
    }
    if (prev_regs->cs != regs->cs) {
        print_reg("cs", regs->cs);
    }
    if (prev_regs->ss != regs->ss) {
        print_reg("ss", regs->ss);
    }
    if (prev_regs->ds != regs->ds) {
        print_reg("ds", regs->ds);
    }
    if (prev_regs->es != regs->es) {
        print_reg("es", regs->es);
    }
    if (prev_regs->fs != regs->fs) {
        print_reg("fs", regs->fs);
    }
    if (prev_regs->gs != regs->gs) {
        print_reg("gs", regs->gs);
    }
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

void read_registers(pid_t pid, user_regs_struct *regs) {
    struct iovec iov = {.iov_base = regs, .iov_len = sizeof(*regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        die("ptrace() failed\n");
    }
}

void write_registers(pid_t pid, user_regs_struct *regs) {
    struct iovec iov = {.iov_base = regs, .iov_len = sizeof(*regs)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
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

int write_assembly(int fd, const char *line) {
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

int run_nasm(const char *infile, const char *outfile) {
    char command[64];
    sprintf(command, "nasm -f bin -o %s %s", outfile, infile);
    if (system(command) != 0) {
        unlink(infile);
        return -1;
    }

    unlink(infile);
    return 0;
}

size_t read_instruction(const char *outfile, unsigned char *data, size_t size) {
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

size_t assemble(const char *line, unsigned char *data, size_t size) {
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

char *parse_call(void) {
    Token tok;
    next_token(&tok);
    if (tok.kind == TOK_EOF) {
        return NULL;
    }

    const char *start = tok.start;
    size_t size = tok.size;

    next_token(&tok);
    // No trailing tokens
    if (tok.kind != TOK_EOF) {
        return NULL;
    }

    char *ret = malloc(size + 1);
    memcpy(ret, start, size);
    ret[size] = '\0';
    return ret;
}

void handle_asm_command(pid_t pid, State *state, const char *line,
                        Token_kind kind) {
    uint64_t rbx = 0;
    unsigned char data[16];
    size_t size;

    char *symbol = NULL;
    if (kind == TOK_CALL) {
        symbol = parse_call();
    }

    if (symbol) {
        // Clear any existing error
        dlerror();

        uint64_t address = (uint64_t)dlsym(RTLD_NEXT, symbol);
        char *error = dlerror();
        if (error != NULL) {
            fprintf(stderr, "%s\n", error);
            return;
        }

        free(symbol);

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

void handle_command(pid_t pid, State *state, const char *line) {
    read_data(pid, state->frame_pointer, state->prev_stack,
              sizeof(state->prev_stack));
    read_registers(pid, &state->prev_regs);

    Token tok;
    next_token(&tok);
    Token_kind kind = tok.kind;
    // No trailing tokens except for call
    if (kind != TOK_CALL) {
        next_token(&tok);
        if (tok.kind != TOK_EOF) {
            kind = TOK_UNKNOWN;
        }
    }

    switch (kind) {
    case TOK_STACK:
        print_stack(state->frame_pointer, state->prev_regs.rsp,
                    state->prev_stack, state->stack, sizeof(state->stack));
        break;
    case TOK_REGS:
        print_regs(&state->prev_regs);
        break;
    case TOK_REG64: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18lx%ld\n", (int)tok.size, tok.start, reg, reg);
        break;
    }
    case TOK_REG32: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x%d\n", (int)tok.size, tok.start, (uint32_t)reg,
               (uint32_t)reg);
        break;
    }
    case TOK_REG16: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x%hd\n", (int)tok.size, tok.start, (uint16_t)reg,
               (uint16_t)reg);
        break;
    }
    case TOK_REG8: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x%hhd\n", (int)tok.size, tok.start, (uint8_t)reg,
               (uint8_t)reg);
        break;
    }
    case TOK_REG8_HIGH: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x%hhd\n", (int)tok.size, tok.start,
               (uint8_t)(reg >> 8), (uint8_t)(reg >> 8));
        break;
    }
    case TOK_REG64_ADDR: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18lx0x%lx\n", (int)tok.size, tok.start, reg, reg);
        break;
    }
    case TOK_REG32_ADDR: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x0x%x\n", (int)tok.size, tok.start, (uint32_t)reg,
               (uint32_t)reg);
        break;
    }
    case TOK_REG16_ADDR: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x0x%x\n", (int)tok.size, tok.start, (uint16_t)reg,
               (uint16_t)reg);
        break;
    }
    case TOK_REG8_ADDR: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        printf("%-15.*s0x%-18x0x%x\n", (int)tok.size, tok.start, (uint8_t)reg,
               (uint8_t)reg);
        break;
    }
    case TOK_EFLAGS: {
        uint64_t reg = *(uint64_t *)((char *)&state->regs + tok.offset);
        print_eflags(reg);
        break;
    }
    default:
        handle_asm_command(pid, state, line, kind);
        break;
    }
}

void init_state(pid_t pid, State *state) {
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

    State state;
    init_state(pid, &state);

    init_lexer();

    char *line;
    while ((line = linenoise("> ")) != NULL) {
        scan_buffer(line);
        linenoiseHistoryAdd(line);
        handle_command(pid, &state, line);
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
