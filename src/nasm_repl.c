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

#include "lexer.h"
#include "linenoise.h"

extern void run_child(void);

#define NOP 0x90

#define STACK_SIZE 128

#define COLOR_RESET "\033[m"
#define COLOR_STACK_DIFF "\033[1;31m"
#define COLOR_RSP "\033[1;34m"

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

struct state {
    unsigned char prev_stack[STACK_SIZE];
    unsigned char stack[STACK_SIZE];
    struct user_regs_struct prev_regs;
    struct user_regs_struct regs;
    uint64_t rip;
    uint64_t frame_pointer;
};

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

void print_reg64(char *name, uint64_t reg) {
    printf("%-15s0x%-18lx%ld\n", name, reg, reg);
}

void print_reg64_addr(char *name, uint64_t reg) {
    printf("%-15s0x%-18lx0x%lx\n", name, reg, reg);
}

void print_reg32(char *name, uint32_t reg) {
    printf("%-15s0x%-18x%d\n", name, reg, reg);
}

void print_reg32_addr(char *name, uint32_t reg) {
    printf("%-15s0x%-18x0x%x\n", name, reg, reg);
}

void print_regs(struct user_regs_struct *regs) {
    print_reg64("rax", regs->rax);
    print_reg64("rbx", regs->rbx);
    print_reg64("rcx", regs->rcx);
    print_reg64("rdx", regs->rdx);
    print_reg64("rsi", regs->rsi);
    print_reg64("rdi", regs->rdi);
    print_reg64_addr("rbp", regs->rbp);
    print_reg64_addr("rsp", regs->rsp);
    print_reg64("r8", regs->r8);
    print_reg64("r9", regs->r9);
    print_reg64("r10", regs->r10);
    print_reg64("r11", regs->r11);
    print_reg64("r12", regs->r12);
    print_reg64("r13", regs->r13);
    print_reg64("r14", regs->r14);
    print_reg64("r15", regs->r15);
    print_reg64_addr("rip", regs->rip);
    print_eflags(regs->eflags);
    print_reg64("cs", regs->cs);
    print_reg64("ss", regs->ss);
    print_reg64("ds", regs->ds);
    print_reg64("es", regs->es);
    print_reg64("fs", regs->fs);
    print_reg64("gs", regs->gs);
}

void print_changed_regs(struct user_regs_struct *prev_regs,
                        struct user_regs_struct *regs) {
    if (prev_regs->rax != regs->rax) {
        print_reg64("rax", regs->rax);
    }
    if (prev_regs->rbx != regs->rbx) {
        print_reg64("rbx", regs->rbx);
    }
    if (prev_regs->rcx != regs->rcx) {
        print_reg64("rcx", regs->rcx);
    }
    if (prev_regs->rdx != regs->rdx) {
        print_reg64("rdx", regs->rdx);
    }
    if (prev_regs->rsi != regs->rsi) {
        print_reg64("rsi", regs->rsi);
    }
    if (prev_regs->rdi != regs->rdi) {
        print_reg64("rdi", regs->rdi);
    }
    if (prev_regs->rbp != regs->rbp) {
        print_reg64_addr("rbp", regs->rbp);
    }
    if (prev_regs->rsp != regs->rsp) {
        print_reg64_addr("rsp", regs->rsp);
    }
    if (prev_regs->r8 != regs->r8) {
        print_reg64("r8", regs->r8);
    }
    if (prev_regs->r9 != regs->r9) {
        print_reg64("r9", regs->r9);
    }
    if (prev_regs->r10 != regs->r10) {
        print_reg64("r10", regs->r10);
    }
    if (prev_regs->r11 != regs->r11) {
        print_reg64("r11", regs->r11);
    }
    if (prev_regs->r12 != regs->r12) {
        print_reg64("r12", regs->r12);
    }
    if (prev_regs->r13 != regs->r13) {
        print_reg64("r13", regs->r13);
    }
    if (prev_regs->r14 != regs->r14) {
        print_reg64("r14", regs->r14);
    }
    if (prev_regs->r15 != regs->r15) {
        print_reg64("r15", regs->r15);
    }
    if (prev_regs->eflags != regs->eflags) {
        print_eflags(regs->eflags);
    }
    if (prev_regs->cs != regs->cs) {
        print_reg64("cs", regs->cs);
    }
    if (prev_regs->ss != regs->ss) {
        print_reg64("ss", regs->ss);
    }
    if (prev_regs->ds != regs->ds) {
        print_reg64("ds", regs->ds);
    }
    if (prev_regs->es != regs->es) {
        print_reg64("es", regs->es);
    }
    if (prev_regs->fs != regs->fs) {
        print_reg64("fs", regs->fs);
    }
    if (prev_regs->gs != regs->gs) {
        print_reg64("gs", regs->gs);
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

char *parse_call(void) {
    next_token();
    if (tok.kind == TOK_EOF) {
        return NULL;
    }

    char *start = tok.start;
    size_t size = tok.size;

    next_token();
    // No trailing tokens
    if (tok.kind != TOK_EOF) {
        return NULL;
    }

    char *ret = malloc(size + 1);
    memcpy(ret, start, size);
    ret[size] = '\0';
    return ret;
}

void handle_asm_command(pid_t pid, struct state *state, char *line) {
    uint64_t rbx = 0;
    unsigned char data[16];
    size_t size;

    char *symbol = NULL;
    if (tok.kind == TOK_CALL) {
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

void handle_command(pid_t pid, struct state *state, char *line) {
    read_data(pid, state->frame_pointer, state->prev_stack,
              sizeof(state->prev_stack));
    read_registers(pid, &state->prev_regs);

    next_token();
    enum token_kind kind = tok.kind;
    // No trailing tokens except for call
    if (kind != TOK_CALL) {
        next_token();
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

    case TOK_RAX:
        print_reg64("rax", state->regs.rax);
        break;
    case TOK_RBX:
        print_reg64("rbx", state->regs.rbx);
        break;
    case TOK_RCX:
        print_reg64("rcx", state->regs.rcx);
        break;
    case TOK_RDX:
        print_reg64("rdx", state->regs.rdx);
        break;
    case TOK_RSI:
        print_reg64("rsi", state->regs.rsi);
        break;
    case TOK_RDI:
        print_reg64("rdi", state->regs.rdi);
        break;
    case TOK_RBP:
        print_reg64_addr("rbp", state->regs.rbp);
        break;
    case TOK_RSP:
        print_reg64_addr("rsp", state->regs.rsp);
        break;
    case TOK_R8:
        print_reg64("r8", state->regs.r8);
        break;
    case TOK_R9:
        print_reg64("r9", state->regs.r9);
        break;
    case TOK_R10:
        print_reg64("r10", state->regs.r10);
        break;
    case TOK_R11:
        print_reg64("r11", state->regs.r11);
        break;
    case TOK_R12:
        print_reg64("r12", state->regs.r12);
        break;
    case TOK_R13:
        print_reg64("r13", state->regs.r13);
        break;
    case TOK_R14:
        print_reg64("r14", state->regs.r14);
        break;
    case TOK_R15:
        print_reg64("r15", state->regs.r15);
        break;

    case TOK_EAX:
        print_reg32("eax", (uint32_t)state->regs.rax);
        break;
    case TOK_EBX:
        print_reg32("ebx", (uint32_t)state->regs.rbx);
        break;
    case TOK_ECX:
        print_reg32("ecx", (uint32_t)state->regs.rcx);
        break;
    case TOK_EDX:
        print_reg32("edx", (uint32_t)state->regs.rdx);
        break;
    case TOK_ESI:
        print_reg32("esi", (uint32_t)state->regs.rsi);
        break;
    case TOK_EDI:
        print_reg32("edi", (uint32_t)state->regs.rdi);
        break;
    case TOK_EBP:
        print_reg32_addr("ebp", (uint32_t)state->regs.rbp);
        break;
    case TOK_ESP:
        print_reg32_addr("esp", (uint32_t)state->regs.rsp);
        break;
    case TOK_R8D:
        print_reg32("r8d", (uint32_t)state->regs.r8);
        break;
    case TOK_R9D:
        print_reg32("r9d", (uint32_t)state->regs.r9);
        break;
    case TOK_R10D:
        print_reg32("r10d", (uint32_t)state->regs.r10);
        break;
    case TOK_R11D:
        print_reg32("r11d", (uint32_t)state->regs.r11);
        break;
    case TOK_R12D:
        print_reg32("r12d", (uint32_t)state->regs.r12);
        break;
    case TOK_R13D:
        print_reg32("r13d", (uint32_t)state->regs.r13);
        break;
    case TOK_R14D:
        print_reg32("r14d", (uint32_t)state->regs.r14);
        break;
    case TOK_R15D:
        print_reg32("r15d", (uint32_t)state->regs.r15);
        break;

    case TOK_RIP:
        print_reg64_addr("rip", state->regs.rip);
        break;
    case TOK_EFLAGS:
        print_eflags(state->regs.eflags);
        break;
    case TOK_CS:
        print_reg64("cs", state->regs.cs);
        break;
    case TOK_SS:
        print_reg64("ss", state->regs.ss);
        break;
    case TOK_DS:
        print_reg64("ds", state->regs.ds);
        break;
    case TOK_ES:
        print_reg64("es", state->regs.es);
        break;
    case TOK_FS:
        print_reg64("fs", state->regs.fs);
        break;
    case TOK_GS:
        print_reg64("gs", state->regs.gs);
        break;
    default:
        handle_asm_command(pid, state, line);
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
        // Init lexer
        ptr = line;
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
