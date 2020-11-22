#include "lexer.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <sys/user.h>

// Must be a power of two
#define MAP_CAPACITY 128

typedef struct user_regs_struct user_regs_struct;
typedef char Command_name[16];

typedef struct Value {
    Token_kind kind;
    size_t offset;
} Value;

typedef struct Map {
    Command_name names[MAP_CAPACITY];
    Value values[MAP_CAPACITY];
} Map;

static Map map;
static const char *buffer;

uint32_t fnv1a(const char *str, size_t size) {
    const unsigned char *s = (const unsigned char *)str;
    uint32_t hash = 0x811c9dc5;

    for (size_t i = 0; i < size; i++) {
        hash ^= s[i];
        hash *= 0x01000193;
    }
    return hash;
}

void add_command(const char *name, Value value) {
    uint32_t i = fnv1a(name, strlen(name));

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strlen(map.names[i]) == 0) {
            strcpy(map.names[i], name);
            map.values[i] = value;
            return;
        }
        i++;
    }
}

Value find_command(const char *name, size_t size) {
    uint32_t i = fnv1a(name, size);

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strlen(map.names[i]) == size &&
            strncmp(name, map.names[i], size) == 0) {
            return map.values[i];
        } else if (strlen(map.names[i]) == 0) {
            return (Value){TOK_UNKNOWN, 0};
        }
        i++;
    }
}

void next_token(Token *tok) {
    while (isspace(*buffer)) {
        buffer++;
    }
    if (*buffer == '\0') {
        tok->kind = TOK_EOF;
    } else {
        tok->start = buffer;
        while (*buffer && *buffer != ' ') {
            buffer++;
        }
        tok->size = (size_t)(buffer - tok->start);
        Value value = find_command(tok->start, tok->size);
        tok->kind = value.kind;
        tok->offset = value.offset;
    }
}

void init_commands(void) {
    add_command("stack", (Value){TOK_STACK, 0});
    add_command("regs", (Value){TOK_REGS, 0});
    add_command("call", (Value){TOK_CALL, 0});

    add_command("rax", (Value){TOK_REG64, offsetof(user_regs_struct, rax)});
    add_command("rbx", (Value){TOK_REG64, offsetof(user_regs_struct, rbx)});
    add_command("rcx", (Value){TOK_REG64, offsetof(user_regs_struct, rcx)});
    add_command("rdx", (Value){TOK_REG64, offsetof(user_regs_struct, rdx)});
    add_command("rsi", (Value){TOK_REG64, offsetof(user_regs_struct, rsi)});
    add_command("rdi", (Value){TOK_REG64, offsetof(user_regs_struct, rdi)});
    add_command("rbp",
                (Value){TOK_REG64_ADDR, offsetof(user_regs_struct, rbp)});
    add_command("rsp",
                (Value){TOK_REG64_ADDR, offsetof(user_regs_struct, rsp)});
    add_command("r8", (Value){TOK_REG64, offsetof(user_regs_struct, r8)});
    add_command("r9", (Value){TOK_REG64, offsetof(user_regs_struct, r9)});
    add_command("r10", (Value){TOK_REG64, offsetof(user_regs_struct, r10)});
    add_command("r11", (Value){TOK_REG64, offsetof(user_regs_struct, r11)});
    add_command("r12", (Value){TOK_REG64, offsetof(user_regs_struct, r12)});
    add_command("r13", (Value){TOK_REG64, offsetof(user_regs_struct, r13)});
    add_command("r14", (Value){TOK_REG64, offsetof(user_regs_struct, r14)});
    add_command("r15", (Value){TOK_REG64, offsetof(user_regs_struct, r15)});

    add_command("eax", (Value){TOK_REG32, offsetof(user_regs_struct, rax)});
    add_command("ebx", (Value){TOK_REG32, offsetof(user_regs_struct, rbx)});
    add_command("ecx", (Value){TOK_REG32, offsetof(user_regs_struct, rcx)});
    add_command("edx", (Value){TOK_REG32, offsetof(user_regs_struct, rdx)});
    add_command("esi", (Value){TOK_REG32, offsetof(user_regs_struct, rsi)});
    add_command("edi", (Value){TOK_REG32, offsetof(user_regs_struct, rdi)});
    add_command("ebp",
                (Value){TOK_REG32_ADDR, offsetof(user_regs_struct, rbp)});
    add_command("esp",
                (Value){TOK_REG32_ADDR, offsetof(user_regs_struct, rsp)});
    add_command("r8d", (Value){TOK_REG32, offsetof(user_regs_struct, r8)});
    add_command("r9d", (Value){TOK_REG32, offsetof(user_regs_struct, r9)});
    add_command("r10d", (Value){TOK_REG32, offsetof(user_regs_struct, r10)});
    add_command("r11d", (Value){TOK_REG32, offsetof(user_regs_struct, r11)});
    add_command("r12d", (Value){TOK_REG32, offsetof(user_regs_struct, r12)});
    add_command("r13d", (Value){TOK_REG32, offsetof(user_regs_struct, r13)});
    add_command("r14d", (Value){TOK_REG32, offsetof(user_regs_struct, r14)});
    add_command("r15d", (Value){TOK_REG32, offsetof(user_regs_struct, r15)});

    add_command("ax", (Value){TOK_REG16, offsetof(user_regs_struct, rax)});
    add_command("bx", (Value){TOK_REG16, offsetof(user_regs_struct, rbx)});
    add_command("cx", (Value){TOK_REG16, offsetof(user_regs_struct, rcx)});
    add_command("dx", (Value){TOK_REG16, offsetof(user_regs_struct, rdx)});
    add_command("si", (Value){TOK_REG16, offsetof(user_regs_struct, rsi)});
    add_command("di", (Value){TOK_REG16, offsetof(user_regs_struct, rdi)});
    add_command("bp", (Value){TOK_REG16_ADDR, offsetof(user_regs_struct, rbp)});
    add_command("sp", (Value){TOK_REG16_ADDR, offsetof(user_regs_struct, rsp)});
    add_command("r8d", (Value){TOK_REG16, offsetof(user_regs_struct, r8)});
    add_command("r9d", (Value){TOK_REG16, offsetof(user_regs_struct, r9)});
    add_command("r10d", (Value){TOK_REG16, offsetof(user_regs_struct, r10)});
    add_command("r11d", (Value){TOK_REG16, offsetof(user_regs_struct, r11)});
    add_command("r12d", (Value){TOK_REG16, offsetof(user_regs_struct, r12)});
    add_command("r13d", (Value){TOK_REG16, offsetof(user_regs_struct, r13)});
    add_command("r14d", (Value){TOK_REG16, offsetof(user_regs_struct, r14)});
    add_command("r15d", (Value){TOK_REG16, offsetof(user_regs_struct, r15)});

    add_command("al", (Value){TOK_REG8, offsetof(user_regs_struct, rax)});
    add_command("bl", (Value){TOK_REG8, offsetof(user_regs_struct, rbx)});
    add_command("cl", (Value){TOK_REG8, offsetof(user_regs_struct, rcx)});
    add_command("dl", (Value){TOK_REG8, offsetof(user_regs_struct, rdx)});
    add_command("sil", (Value){TOK_REG8, offsetof(user_regs_struct, rsi)});
    add_command("dil", (Value){TOK_REG8, offsetof(user_regs_struct, rdi)});
    add_command("bpl", (Value){TOK_REG8_ADDR, offsetof(user_regs_struct, rbp)});
    add_command("spl", (Value){TOK_REG8_ADDR, offsetof(user_regs_struct, rsp)});
    add_command("r8b", (Value){TOK_REG8, offsetof(user_regs_struct, r8)});
    add_command("r9b", (Value){TOK_REG8, offsetof(user_regs_struct, r9)});
    add_command("r10b", (Value){TOK_REG8, offsetof(user_regs_struct, r10)});
    add_command("r11b", (Value){TOK_REG8, offsetof(user_regs_struct, r11)});
    add_command("r12b", (Value){TOK_REG8, offsetof(user_regs_struct, r12)});
    add_command("r13b", (Value){TOK_REG8, offsetof(user_regs_struct, r13)});
    add_command("r14b", (Value){TOK_REG8, offsetof(user_regs_struct, r14)});
    add_command("r15b", (Value){TOK_REG8, offsetof(user_regs_struct, r15)});

    add_command("ah", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rax)});
    add_command("bh", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rbx)});
    add_command("ch", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rcx)});
    add_command("dh", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rdx)});

    add_command("rip",
                (Value){TOK_REG64_ADDR, offsetof(user_regs_struct, rip)});
    add_command("eflags",
                (Value){TOK_EFLAGS, offsetof(user_regs_struct, eflags)});
    add_command("cs", (Value){TOK_REG64, offsetof(user_regs_struct, cs)});
    add_command("ss", (Value){TOK_REG64, offsetof(user_regs_struct, ss)});
    add_command("ds", (Value){TOK_REG64, offsetof(user_regs_struct, ds)});
    add_command("es", (Value){TOK_REG64, offsetof(user_regs_struct, es)});
    add_command("fs", (Value){TOK_REG64, offsetof(user_regs_struct, fs)});
    add_command("gs", (Value){TOK_REG64, offsetof(user_regs_struct, gs)});
}

void init_lexer(const char *line) { buffer = line; }
