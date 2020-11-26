# NASM REPL

A x86-64 assembly REPL for Linux. [NASM](https://nasm.us/) is used to assemble instructions, and [ptrace](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) is used to write and execute them in a child process.

## Installation

```
mkdir build
cd build
cmake ..
make
```

## Features

Type an instruction to execute it. Any register that has changed will be printed.

```
> mov rax, 0xff
rax = 255  0xff
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

Use the call instruction to call functions in the C standard library:

```
> mov rax, "hello"
> push rax
> mov rdi, rsp
> call puts
```

Use LD_PRELOAD to call functions in an external library:

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
255  0xff
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
