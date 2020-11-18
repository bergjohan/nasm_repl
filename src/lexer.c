#include "lexer.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

// Must be a power of two
#define MAP_CAPACITY 32

typedef char command_name[16];

struct map {
    command_name name[MAP_CAPACITY];
    enum token_kind kind[MAP_CAPACITY];
};

static struct map map;

char *ptr;
struct token tok;

uint32_t fnv1a(char *str, size_t size) {
    unsigned char *s = (unsigned char *)str;
    uint32_t hash = 0x811c9dc5;

    for (size_t i = 0; i < size; i++) {
        hash ^= s[i];
        hash *= 0x01000193;
    }
    return hash;
}

void add_command(char *name, enum token_kind kind) {
    uint32_t i = fnv1a(name, strlen(name));

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strlen(map.name[i]) == 0) {
            strcpy(map.name[i], name);
            map.kind[i] = kind;
            return;
        }
        i++;
    }
}

enum token_kind find_command(char *name, size_t size) {
    uint32_t i = fnv1a(name, size);

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strncmp(name, map.name[i], size) == 0) {
            return map.kind[i];
        } else if (strlen(map.name[i]) == 0) {
            return TOK_UNKNOWN;
        }
        i++;
    }
}

void next_token(void) {
    while (isspace(*ptr)) {
        ptr++;
    }
    if (*ptr == '\0') {
        tok.kind = TOK_EOF;
    } else {
        tok.start = ptr;
        while (*ptr && *ptr != ' ') {
            ptr++;
        }
        tok.end = ptr;
        tok.kind = find_command(tok.start, (size_t)(tok.end - tok.start));
    }
}

void init_commands(void) {
    add_command("stack", TOK_STACK);
    add_command("regs", TOK_REGS);
    add_command("call", TOK_CALL);
    add_command("rax", TOK_RAX);
    add_command("rbx", TOK_RBX);
    add_command("rcx", TOK_RCX);
    add_command("rdx", TOK_RDX);
    add_command("rsi", TOK_RSI);
    add_command("rdi", TOK_RDI);
    add_command("rbp", TOK_RBP);
    add_command("rsp", TOK_RSP);
    add_command("r8", TOK_R8);
    add_command("r9", TOK_R9);
    add_command("r10", TOK_R10);
    add_command("r11", TOK_R11);
    add_command("r12", TOK_R12);
    add_command("r13", TOK_R13);
    add_command("r14", TOK_R14);
    add_command("r15", TOK_R15);
    add_command("rip", TOK_RIP);
    add_command("eflags", TOK_EFLAGS);
    add_command("cs", TOK_CS);
    add_command("ss", TOK_SS);
    add_command("ds", TOK_DS);
    add_command("es", TOK_ES);
    add_command("fs", TOK_FS);
    add_command("gs", TOK_GS);
}
