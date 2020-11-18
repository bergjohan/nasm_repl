#pragma once

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
    char *start;
    char *end;
    enum token_kind kind;
};

extern char *ptr;
extern struct token tok;

void next_token(void);
void init_commands(void);
