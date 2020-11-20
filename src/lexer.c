#include "lexer.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

// Must be a power of two
#define MAP_CAPACITY 128

typedef char command_name[16];

struct map {
    command_name names[MAP_CAPACITY];
    enum token_kind kinds[MAP_CAPACITY];
};

static struct map map;
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

void add_command(const char *name, enum token_kind kind) {
    uint32_t i = fnv1a(name, strlen(name));

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strlen(map.names[i]) == 0) {
            strcpy(map.names[i], name);
            map.kinds[i] = kind;
            return;
        }
        i++;
    }
}

enum token_kind find_command(const char *name, size_t size) {
    uint32_t i = fnv1a(name, size);

    for (;;) {
        i &= MAP_CAPACITY - 1;
        if (strlen(map.names[i]) == size &&
            strncmp(name, map.names[i], size) == 0) {
            return map.kinds[i];
        } else if (strlen(map.names[i]) == 0) {
            return TOK_UNKNOWN;
        }
        i++;
    }
}

void next_token(struct token *tok) {
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
        tok->kind = find_command(tok->start, tok->size);
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

    add_command("eax", TOK_EAX);
    add_command("ebx", TOK_EBX);
    add_command("ecx", TOK_ECX);
    add_command("edx", TOK_EDX);
    add_command("esi", TOK_ESI);
    add_command("edi", TOK_EDI);
    add_command("ebp", TOK_EBP);
    add_command("esp", TOK_ESP);
    add_command("r8d", TOK_R8D);
    add_command("r9d", TOK_R9D);
    add_command("r10d", TOK_R10D);
    add_command("r11d", TOK_R11D);
    add_command("r12d", TOK_R12D);
    add_command("r13d", TOK_R13D);
    add_command("r14d", TOK_R14D);
    add_command("r15d", TOK_R15D);

    add_command("ax", TOK_AX);
    add_command("bx", TOK_BX);
    add_command("cx", TOK_CX);
    add_command("dx", TOK_DX);
    add_command("si", TOK_SI);
    add_command("di", TOK_DI);
    add_command("bp", TOK_BP);
    add_command("sp", TOK_SP);
    add_command("r8w", TOK_R8W);
    add_command("r9w", TOK_R9W);
    add_command("r10w", TOK_R10W);
    add_command("r11w", TOK_R11W);
    add_command("r12w", TOK_R12W);
    add_command("r13w", TOK_R13W);
    add_command("r14w", TOK_R14W);
    add_command("r15w", TOK_R15W);

    add_command("al", TOK_AL);
    add_command("bl", TOK_BL);
    add_command("cl", TOK_CL);
    add_command("dl", TOK_DL);
    add_command("ah", TOK_AH);
    add_command("bh", TOK_BH);
    add_command("ch", TOK_CH);
    add_command("dh", TOK_DH);
    add_command("sil", TOK_SIL);
    add_command("dil", TOK_DIL);
    add_command("bpl", TOK_BPL);
    add_command("spl", TOK_SPL);
    add_command("r8b", TOK_R8B);
    add_command("r9b", TOK_R9B);
    add_command("r10b", TOK_R10B);
    add_command("r11b", TOK_R11B);
    add_command("r12b", TOK_R12B);
    add_command("r13b", TOK_R13B);
    add_command("r14b", TOK_R14B);
    add_command("r15b", TOK_R15B);

    add_command("rip", TOK_RIP);
    add_command("eflags", TOK_EFLAGS);
    add_command("cs", TOK_CS);
    add_command("ss", TOK_SS);
    add_command("ds", TOK_DS);
    add_command("es", TOK_ES);
    add_command("fs", TOK_FS);
    add_command("gs", TOK_GS);
}

void init_lexer(const char *line) { buffer = line; }
