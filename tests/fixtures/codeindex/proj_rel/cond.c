#include "inc/cond.h"

int cond_use(void)
{
    return 1;
}

int cond_entry(void)
{
#if FEATURE > 4
    return cond_use();
#else
    return 0;
#endif
}
