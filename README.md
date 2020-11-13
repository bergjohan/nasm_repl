# NASM REPL

A x86-64 assembly REPL for Linux. [NASM](https://nasm.us/) is used to assemble instructions, and [ptrace](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) is used to write and execute them in a child process.

## Features

Type an instruction to execute it. Any register that has changed will be printed.

```
> mov rax, 0xff
rax            0xff                255
```

Changes to the stack memory will also be printed. Changed bytes are colored in red, and the position of rsp is colored in blue (not visible here):

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

It's possible to call functions in the C standard library:

> mov rax, "hello"
> push rax
> mov rdi, rsp
> call puts

It's even possible to call functions in your own libraries by using LD_PRELOAD:

```
$ cat foo.c
int square(int num) {
    return num * num;
}

$ gcc -c -fpic foo.c
$ gcc -shared -o libfoo.so foo.o
$ LD_PRELOAD=./libfoo.so ./nasm_repl
> mov rdi, 4
> call square
```

## Commands

Type a register name to print its value:

```
> rax
rax            0xff                255
```

To print all registers, use the `regs` command:

```
> regs
rax            0x0                 0
rbx            0x0                 0
rcx            0x0                 0
rdx            0x0                 0
rsi            0x0                 0
rdi            0x0                 0
rbp            0x7ffc29804130      0x7ffc29804130
rsp            0x7ffc29804118      0x7ffc29804118
r8             0xffffffff          4294967295
r9             0x7fec7c34b5c0      140653672838592
r10            0x0                 0
r11            0x286               646
r12            0x559fa74103a0      94144194216864
r13            0x0                 0
r14            0x0                 0
r15            0x0                 0
rip            0x559fa74128d1      0x559fa74128d1
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
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
