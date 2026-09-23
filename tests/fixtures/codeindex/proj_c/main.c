#include "inc/util.h"
#include <stdio.h>

int g_counter = 0;

void (*on_tick)(int);

int main(void)
{
    int r = add(2, 3);
    printf("%d\n", r);
    on_tick(r);
    return 0;
}
