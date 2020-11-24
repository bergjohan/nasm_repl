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

uint32_t hash(const char *str, size_t size) {
    const unsigned char *s = (const unsigned char *)str;
    uint32_t hash = 0x811c9dc5;

    for (size_t i = 0; i < size; i++) {
        hash ^= s[i];
        hash *= 0x01000193;
    }
    return hash;
}

void map_insert(const char *name, Value value) {
    uint32_t i = hash(name, strlen(name));

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

Value map_find(const char *name, size_t size) {
    uint32_t i = hash(name, size);

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
        Value value = map_find(tok->start, tok->size);
        tok->kind = value.kind;
        tok->offset = value.offset;
    }
}

void init_lexer(void) {
    map_insert("stack", (Value){TOK_STACK, 0});
    map_insert("call", (Value){TOK_CALL, 0});

    map_insert("rax", (Value){TOK_REG64, offsetof(user_regs_struct, rax)});
    map_insert("rbx", (Value){TOK_REG64, offsetof(user_regs_struct, rbx)});
    map_insert("rcx", (Value){TOK_REG64, offsetof(user_regs_struct, rcx)});
    map_insert("rdx", (Value){TOK_REG64, offsetof(user_regs_struct, rdx)});
    map_insert("rsi", (Value){TOK_REG64, offsetof(user_regs_struct, rsi)});
    map_insert("rdi", (Value){TOK_REG64, offsetof(user_regs_struct, rdi)});
    map_insert("rbp", (Value){TOK_REG64, offsetof(user_regs_struct, rbp)});
    map_insert("rsp", (Value){TOK_REG64, offsetof(user_regs_struct, rsp)});
    map_insert("r8", (Value){TOK_REG64, offsetof(user_regs_struct, r8)});
    map_insert("r9", (Value){TOK_REG64, offsetof(user_regs_struct, r9)});
    map_insert("r10", (Value){TOK_REG64, offsetof(user_regs_struct, r10)});
    map_insert("r11", (Value){TOK_REG64, offsetof(user_regs_struct, r11)});
    map_insert("r12", (Value){TOK_REG64, offsetof(user_regs_struct, r12)});
    map_insert("r13", (Value){TOK_REG64, offsetof(user_regs_struct, r13)});
    map_insert("r14", (Value){TOK_REG64, offsetof(user_regs_struct, r14)});
    map_insert("r15", (Value){TOK_REG64, offsetof(user_regs_struct, r15)});

    map_insert("eax", (Value){TOK_REG32, offsetof(user_regs_struct, rax)});
    map_insert("ebx", (Value){TOK_REG32, offsetof(user_regs_struct, rbx)});
    map_insert("ecx", (Value){TOK_REG32, offsetof(user_regs_struct, rcx)});
    map_insert("edx", (Value){TOK_REG32, offsetof(user_regs_struct, rdx)});
    map_insert("esi", (Value){TOK_REG32, offsetof(user_regs_struct, rsi)});
    map_insert("edi", (Value){TOK_REG32, offsetof(user_regs_struct, rdi)});
    map_insert("ebp", (Value){TOK_REG32, offsetof(user_regs_struct, rbp)});
    map_insert("esp", (Value){TOK_REG32, offsetof(user_regs_struct, rsp)});
    map_insert("r8d", (Value){TOK_REG32, offsetof(user_regs_struct, r8)});
    map_insert("r9d", (Value){TOK_REG32, offsetof(user_regs_struct, r9)});
    map_insert("r10d", (Value){TOK_REG32, offsetof(user_regs_struct, r10)});
    map_insert("r11d", (Value){TOK_REG32, offsetof(user_regs_struct, r11)});
    map_insert("r12d", (Value){TOK_REG32, offsetof(user_regs_struct, r12)});
    map_insert("r13d", (Value){TOK_REG32, offsetof(user_regs_struct, r13)});
    map_insert("r14d", (Value){TOK_REG32, offsetof(user_regs_struct, r14)});
    map_insert("r15d", (Value){TOK_REG32, offsetof(user_regs_struct, r15)});

    map_insert("ax", (Value){TOK_REG16, offsetof(user_regs_struct, rax)});
    map_insert("bx", (Value){TOK_REG16, offsetof(user_regs_struct, rbx)});
    map_insert("cx", (Value){TOK_REG16, offsetof(user_regs_struct, rcx)});
    map_insert("dx", (Value){TOK_REG16, offsetof(user_regs_struct, rdx)});
    map_insert("si", (Value){TOK_REG16, offsetof(user_regs_struct, rsi)});
    map_insert("di", (Value){TOK_REG16, offsetof(user_regs_struct, rdi)});
    map_insert("bp", (Value){TOK_REG16, offsetof(user_regs_struct, rbp)});
    map_insert("sp", (Value){TOK_REG16, offsetof(user_regs_struct, rsp)});
    map_insert("r8d", (Value){TOK_REG16, offsetof(user_regs_struct, r8)});
    map_insert("r9d", (Value){TOK_REG16, offsetof(user_regs_struct, r9)});
    map_insert("r10d", (Value){TOK_REG16, offsetof(user_regs_struct, r10)});
    map_insert("r11d", (Value){TOK_REG16, offsetof(user_regs_struct, r11)});
    map_insert("r12d", (Value){TOK_REG16, offsetof(user_regs_struct, r12)});
    map_insert("r13d", (Value){TOK_REG16, offsetof(user_regs_struct, r13)});
    map_insert("r14d", (Value){TOK_REG16, offsetof(user_regs_struct, r14)});
    map_insert("r15d", (Value){TOK_REG16, offsetof(user_regs_struct, r15)});

    map_insert("al", (Value){TOK_REG8, offsetof(user_regs_struct, rax)});
    map_insert("bl", (Value){TOK_REG8, offsetof(user_regs_struct, rbx)});
    map_insert("cl", (Value){TOK_REG8, offsetof(user_regs_struct, rcx)});
    map_insert("dl", (Value){TOK_REG8, offsetof(user_regs_struct, rdx)});
    map_insert("sil", (Value){TOK_REG8, offsetof(user_regs_struct, rsi)});
    map_insert("dil", (Value){TOK_REG8, offsetof(user_regs_struct, rdi)});
    map_insert("bpl", (Value){TOK_REG8, offsetof(user_regs_struct, rbp)});
    map_insert("spl", (Value){TOK_REG8, offsetof(user_regs_struct, rsp)});
    map_insert("r8b", (Value){TOK_REG8, offsetof(user_regs_struct, r8)});
    map_insert("r9b", (Value){TOK_REG8, offsetof(user_regs_struct, r9)});
    map_insert("r10b", (Value){TOK_REG8, offsetof(user_regs_struct, r10)});
    map_insert("r11b", (Value){TOK_REG8, offsetof(user_regs_struct, r11)});
    map_insert("r12b", (Value){TOK_REG8, offsetof(user_regs_struct, r12)});
    map_insert("r13b", (Value){TOK_REG8, offsetof(user_regs_struct, r13)});
    map_insert("r14b", (Value){TOK_REG8, offsetof(user_regs_struct, r14)});
    map_insert("r15b", (Value){TOK_REG8, offsetof(user_regs_struct, r15)});

    map_insert("ah", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rax)});
    map_insert("bh", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rbx)});
    map_insert("ch", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rcx)});
    map_insert("dh", (Value){TOK_REG8_HIGH, offsetof(user_regs_struct, rdx)});

    map_insert("rip", (Value){TOK_REG64, offsetof(user_regs_struct, rip)});
    map_insert("eflags",
               (Value){TOK_EFLAGS, offsetof(user_regs_struct, eflags)});
    map_insert("cs", (Value){TOK_REG64, offsetof(user_regs_struct, cs)});
    map_insert("ss", (Value){TOK_REG64, offsetof(user_regs_struct, ss)});
    map_insert("ds", (Value){TOK_REG64, offsetof(user_regs_struct, ds)});
    map_insert("es", (Value){TOK_REG64, offsetof(user_regs_struct, es)});
    map_insert("fs", (Value){TOK_REG64, offsetof(user_regs_struct, fs)});
    map_insert("gs", (Value){TOK_REG64, offsetof(user_regs_struct, gs)});

    map_insert("xmm0", (Value){TOK_XMM, 0});
    map_insert("xmm1", (Value){TOK_XMM, 4});
    map_insert("xmm2", (Value){TOK_XMM, 8});
    map_insert("xmm3", (Value){TOK_XMM, 12});
    map_insert("xmm4", (Value){TOK_XMM, 16});
    map_insert("xmm5", (Value){TOK_XMM, 20});
    map_insert("xmm6", (Value){TOK_XMM, 24});
    map_insert("xmm7", (Value){TOK_XMM, 28});
    map_insert("xmm8", (Value){TOK_XMM, 32});
    map_insert("xmm9", (Value){TOK_XMM, 36});
    map_insert("xmm10", (Value){TOK_XMM, 40});
    map_insert("xmm11", (Value){TOK_XMM, 44});
    map_insert("xmm12", (Value){TOK_XMM, 48});
    map_insert("xmm13", (Value){TOK_XMM, 52});
    map_insert("xmm14", (Value){TOK_XMM, 56});
    map_insert("xmm15", (Value){TOK_XMM, 60});
}

void scan_buffer(const char *line) { buffer = line; }
