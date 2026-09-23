#include <stdio.h>
#include "inc/util.h"
#include "inc/alt.h"

static int helper_local(int x)
{
    return x + 1;
}

int main(void)
{
    int r = util_add(1, 2) + helper_local(1) + alt_ping();
    printf("%d\n", r);
    return r;
}
