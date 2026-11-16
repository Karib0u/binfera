# gcc's position-independent i386 code: the function finds the GOT through
# __x86.get_pc_thunk.bx and reads a global relative to it. clang never emits the thunk.
    .text
    .globl add_counter
    .type add_counter, @function
add_counter:
    pushl %ebx
    call __x86.get_pc_thunk.bx
    addl $_GLOBAL_OFFSET_TABLE_, %ebx
    movl counter@GOTOFF(%ebx), %eax
    addl 8(%esp), %eax
    popl %ebx
    ret
    .size add_counter, .-add_counter

    .globl _start
    .type _start, @function
_start:
    pushl $1
    call add_counter
    addl $4, %esp
    movl %eax, %ebx
    movl $1, %eax
    int $0x80

    .section .text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
    .globl __x86.get_pc_thunk.bx
    .hidden __x86.get_pc_thunk.bx
    .type __x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
    movl (%esp), %ebx
    ret

    .data
counter:
    .long 41
