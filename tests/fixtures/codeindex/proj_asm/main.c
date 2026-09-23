#include <stdio.h>
#include "inc/api.h"

int c_helper(int x)
{
    return x + 1;
}

int use_asm(void)
{
    int v = 0;
    asm_entry();          /* 声明在 api.h 里可见 → exact */
    gnu_entry();          /* 全工程有定义、但调用点看不到声明 → name-only */
    v = c_helper(v);
    printf("%d", v);      /* 系统函数 → blind */
    return v;
}
