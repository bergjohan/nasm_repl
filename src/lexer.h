#pragma once

#include <stddef.h>

typedef enum Token_kind {
    TOK_UNKNOWN,
    TOK_EOF,
    TOK_STACK,
    TOK_CALL,
    TOK_REG64,
    TOK_REG32,
    TOK_REG16,
    TOK_REG8,
    TOK_REG8_HIGH,
    TOK_EFLAGS,
    TOK_XMM
} Token_kind;

typedef struct Token {
    const char *start;
    size_t size;
    Token_kind kind;
    size_t offset;
} Token;

void next_token(Token *tok);
void init_lexer(void);
void scan_buffer(const char *line);
