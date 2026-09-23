#include "inc/cb.h"

static int cb_impl(int x)
{
    return x * 2;
}

int (*cb_hook)(int);

int cb_set(void)
{
    cb_hook = cb_impl;
    return 0;
}

int cb_run(int x)
{
    return cb_hook(x);
}
