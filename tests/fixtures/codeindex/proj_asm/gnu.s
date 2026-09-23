/* GNU as 风格的汇编样本 */
    .text
    .globl  gnu_entry
    .type   gnu_entry, %function

gnu_entry:
    push    {r4, lr}
    bl      c_helper
    bl      gnu_entry
    pop     {r4, pc}

    .macro  gnu_mac
    bl      c_helper
    .endm

    .word   gnu_entry

    .section .rodata
gnu_data:
    .word   0x11
