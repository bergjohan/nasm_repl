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

int handle_reg_command(char *line, struct user_regs_struct *regs) {
    if (strcmp(line, "rax") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rax", regs->rax, regs->rax);
    } else if (strcmp(line, "rbx") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rbx", regs->rbx, regs->rbx);
    } else if (strcmp(line, "rcx") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rcx", regs->rcx, regs->rcx);
    } else if (strcmp(line, "rdx") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rdx", regs->rdx, regs->rdx);
    } else if (strcmp(line, "rsi") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rsi", regs->rsi, regs->rsi);
    } else if (strcmp(line, "rdi") == 0) {
        printf("%-15s0x%-18llx%lld\n", "rdi", regs->rdi, regs->rdi);
    } else if (strcmp(line, "rbp") == 0) {
        printf("%-15s0x%-18llx0x%llx\n", "rbp", regs->rbp, regs->rbp);
    } else if (strcmp(line, "rsp") == 0) {
        printf("%-15s0x%-18llx0x%llx\n", "rsp", regs->rsp, regs->rsp);
    } else if (strcmp(line, "r8") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r8", regs->r8, regs->r8);
    } else if (strcmp(line, "r9") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r9", regs->r9, regs->r9);
    } else if (strcmp(line, "r10") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r10", regs->r10, regs->r10);
    } else if (strcmp(line, "r11") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r11", regs->r11, regs->r11);
    } else if (strcmp(line, "r12") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r12", regs->r12, regs->r12);
    } else if (strcmp(line, "r13") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r13", regs->r13, regs->r13);
    } else if (strcmp(line, "r14") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r14", regs->r14, regs->r14);
    } else if (strcmp(line, "r15") == 0) {
        printf("%-15s0x%-18llx%lld\n", "r15", regs->r15, regs->r15);
    } else if (strcmp(line, "rip") == 0) {
        printf("%-15s0x%-18llx0x%llx\n", "rip", regs->rip, regs->rip);
    } else if (strcmp(line, "eflags") == 0) {
        print_eflags(regs->eflags);
    } else if (strcmp(line, "cs") == 0) {
        printf("%-15s0x%-18llx%lld\n", "cs", regs->cs, regs->cs);
    } else if (strcmp(line, "ss") == 0) {
        printf("%-15s0x%-18llx%lld\n", "ss", regs->ss, regs->ss);
    } else if (strcmp(line, "ds") == 0) {
        printf("%-15s0x%-18llx%lld\n", "ds", regs->ds, regs->ds);
    } else if (strcmp(line, "es") == 0) {
        printf("%-15s0x%-18llx%lld\n", "es", regs->es, regs->es);
    } else if (strcmp(line, "fs") == 0) {
        printf("%-15s0x%-18llx%lld\n", "fs", regs->fs, regs->fs);
    } else if (strcmp(line, "gs") == 0) {
        printf("%-15s0x%-18llx%lld\n", "gs", regs->gs, regs->gs);
    } else {
        return -1;
    }
    return 0;
}

void read_stack(pid_t pid, uint64_t frame_pointer, unsigned char *buf,
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

void write_instruction(pid_t pid, uint64_t address, unsigned char *data) {
    if (ptrace(PTRACE_POKEDATA, pid, address, to_u64(data)) == -1) {
        die("ptrace() failed\n");
    }
    if (ptrace(PTRACE_POKEDATA, pid, address + 8, to_u64(&data[8])) == -1) {
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

    // Pad with nops
    memset(data, NOP, size);

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

void run(pid_t pid) {
    unsigned char prev_stack[STACK_SIZE];
    unsigned char stack[STACK_SIZE];
    struct user_regs_struct prev_regs;
    struct user_regs_struct regs;

    // Since we'll be using memcmp
    memset(&prev_regs, 0, sizeof(prev_regs));
    memset(&regs, 0, sizeof(regs));

    if (waitpid(pid, NULL, 0) == -1) {
        die("waitpid() failed\n");
    }

    read_registers(pid, &regs);
    uint64_t rip = regs.rip;
    uint64_t frame_pointer = regs.rsp;
    read_stack(pid, frame_pointer, stack, sizeof(stack));

    char *line;
    while ((line = linenoise("> ")) != NULL) {
        linenoiseHistoryAdd(line);

        read_stack(pid, frame_pointer, prev_stack, sizeof(prev_stack));
        read_registers(pid, &prev_regs);

        uint64_t rbx = 0;
        unsigned char data[16];
        if (strcmp(line, "stack") == 0) {
            print_stack(frame_pointer, prev_regs.rsp, prev_stack, stack,
                        sizeof(stack));
            linenoiseFree(line);
            continue;
        } else if (strcmp(line, "regs") == 0) {
            print_regs(&prev_regs);
            linenoiseFree(line);
            continue;
        } else if (handle_reg_command(line, &prev_regs) == 0) {
            linenoiseFree(line);
            continue;
        } else if (strncmp(line, "call", 4) == 0) {
            const char *symbol = line + 4;
            while (isspace(*symbol)) {
                symbol++;
            }

            // Clear any existing error
            dlerror();

            uint64_t address = (uint64_t)dlsym(RTLD_NEXT, symbol);
            char *error = dlerror();
            if (error != NULL) {
                fprintf(stderr, "%s\n", error);
                linenoiseFree(line);
                continue;
            }

            // Save rbx
            rbx = prev_regs.rbx;

            prev_regs.rbx = address;
            write_registers(pid, &prev_regs);

            if (assemble("call rbx", data, sizeof(data)) == 0) {
                linenoiseFree(line);
                continue;
            }
        } else {
            if (assemble(line, data, sizeof(data)) == 0) {
                linenoiseFree(line);
                continue;
            }
        }

        linenoiseFree(line);

        write_instruction(pid, rip, data);
        execute_instruction(pid);

        read_stack(pid, frame_pointer, stack, sizeof(stack));
        read_registers(pid, &regs);

        // Restore rbx
        if (rbx != 0 && prev_regs.rbx == regs.rbx) {
            prev_regs.rbx = rbx;
            regs.rbx = rbx;
            write_registers(pid, &regs);
        }

        if (memcmp(prev_stack, stack, sizeof(stack)) != 0) {
            print_stack(frame_pointer, regs.rsp, prev_stack, stack,
                        sizeof(stack));
        }

        if (memcmp(&prev_regs, &regs, sizeof(regs)) != 0) {
            print_changed_regs(&prev_regs, &regs);
        }
    }

    // Move rip to ret instruction (16 nop's + one jmp)
    regs.rip += 16 + 2;
    // Restore stack pointer
    regs.rsp = frame_pointer;
    write_registers(pid, &regs);
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
