; armasm 风格的汇编样本（批次70 fixture）
        AREA    |.text|, CODE, READONLY
        GET     asm_defs.s
        EXPORT  asm_entry
        IMPORT  c_helper
        IMPORT  d_helper

asm_entry       PROC
        IF {FPU} != "SoftVFP"
        PUSH    {R4-R7, LR}
        BL      asm_local
        ENDIF
        LDR     R2, =c_helper
        BLX     R2
        BL      c_helper
        BL      defs_func
        BLX     R3
        B       d_helper
        POP     {R4-R7, PC}
        ENDP

asm_local       PROC
        BX      LR
        ENDP

CALL_TWICE      MACRO
        BL      c_helper
        MEND

endpend
        END
