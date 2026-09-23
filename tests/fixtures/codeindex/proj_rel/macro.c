#include "inc/macro.h"

int macro_target(void)
{
    return 1;
}

int macro_user(void)
{
    return CALL_IT() + macro_target();
}
