#pragma once

#include <stddef.h>

enum token_kind {
    TOK_UNKNOWN,
    TOK_EOF,
    TOK_STACK,
    TOK_REGS,
    TOK_CALL,

    TOK_RAX,
    TOK_RBX,
    TOK_RCX,
    TOK_RDX,
    TOK_RSI,
    TOK_RDI,
    TOK_RBP,
    TOK_RSP,
    TOK_R8,
    TOK_R9,
    TOK_R10,
    TOK_R11,
    TOK_R12,
    TOK_R13,
    TOK_R14,
    TOK_R15,

    TOK_EAX,
    TOK_EBX,
    TOK_ECX,
    TOK_EDX,
    TOK_ESI,
    TOK_EDI,
    TOK_EBP,
    TOK_ESP,
    TOK_R8D,
    TOK_R9D,
    TOK_R10D,
    TOK_R11D,
    TOK_R12D,
    TOK_R13D,
    TOK_R14D,
    TOK_R15D,

    TOK_AX,
    TOK_BX,
    TOK_CX,
    TOK_DX,
    TOK_SI,
    TOK_DI,
    TOK_BP,
    TOK_SP,
    TOK_R8W,
    TOK_R9W,
    TOK_R10W,
    TOK_R11W,
    TOK_R12W,
    TOK_R13W,
    TOK_R14W,
    TOK_R15W,

    TOK_AL,
    TOK_BL,
    TOK_CL,
    TOK_DL,
    TOK_AH,
    TOK_BH,
    TOK_CH,
    TOK_DH,
    TOK_SIL,
    TOK_DIL,
    TOK_BPL,
    TOK_SPL,
    TOK_R8B,
    TOK_R9B,
    TOK_R10B,
    TOK_R11B,
    TOK_R12B,
    TOK_R13B,
    TOK_R14B,
    TOK_R15B,

    TOK_RIP,
    TOK_EFLAGS,
    TOK_CS,
    TOK_SS,
    TOK_DS,
    TOK_ES,
    TOK_FS,
    TOK_GS
};

struct token {
    const char *start;
    size_t size;
    enum token_kind kind;
};

void next_token(struct token *tok);
void init_commands(void);
void init_lexer(const char *line);
