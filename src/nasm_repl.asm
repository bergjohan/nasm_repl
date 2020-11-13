section .text
global run_child
run_child:
    ; Breakpoint
    int3
    ; Pad with 16 bytes for writing instructions
    %rep 16
    nop
    %endrep
    jmp run_child
    ret
