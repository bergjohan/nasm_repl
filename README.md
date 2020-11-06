# NASM REPL

A x86-64 assembly REPL for Linux. [NASM](https://nasm.us/) is used to assemble instructions, and [ptrace](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) is used to write and execute them in a child process.

## Commands

Type an instruction to execute it. Any register that has changed will be printed.

```
> mov rax, 0xff
rax = 0xff
```

Changes to the stack memory will also be printed. Changed bytes are colored in red:

```
> mov byte [rsp-1], 0xff
7ffe2dfafc88  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffe2dfafc98  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffe2dfafca8  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
7ffe2dfafcb8  10 fd fa 2d fe 7f 00 00  d0 fc fa 2d fe 7f 00 00  |...-.......-....|
7ffe2dfafcc8  00 33 8a 4b 21 ef 49 95  00 00 00 00 00 00 00 00  |.3.K!.I.........|
7ffe2dfafcd8  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffe2dfafce8  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffe2dfafcf8  a0 31 0c 30 8d 7f 00 00  25 00 00 00 00 00 00 ff  |.1.0....%.......|
```

Type a register name to print its value:

```
> rax
rax = 0xff
```

To print all registers, use the `regs` command:

```
> regs
r15 = 0
r14 = 0
r13 = 0
r12 = 0x559f17bf53a0
rbp = 0x7ffea75e4f20
rbx = 0
r11 = 0x286
r10 = 0
r9 = 0x7fd7a71ef5c0
r8 = 0xffffffff
rax = 0
rcx = 0
rdx = 0
rsi = 0
rdi = 0
orig_rax = 0xffffffffffffffff
rip = 0x559f17bf72c1
cs = 0x33
eflags = 0x202
rsp = 0x7ffea75e4f08
ss = 0x2b
fs_base = 0x7fd7a71ef5c0
gs_base = 0
ds = 0
es = 0
fs = 0
gs = 0
```

To print the stack memory, use the `stack` command:

```
> stack
7ffdd7209078  00 00 00 00 00 00 00 00  02 00 00 00 00 00 00 00  |................|
7ffdd7209088  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffdd7209098  00 00 00 00 00 00 00 00  08 00 00 00 00 00 00 00  |................|
7ffdd72090a8  00 91 20 d7 fd 7f 00 00  c0 90 20 d7 fd 7f 00 00  |.. ....... .....|
7ffdd72090b8  00 6c d4 f0 8c d6 e2 af  00 00 00 00 00 00 00 00  |.l..............|
7ffdd72090c8  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffdd72090d8  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
7ffdd72090e8  a0 01 7e 86 08 7f 00 00  25 00 00 00 00 00 00 00  |..~.....%.......|
```
