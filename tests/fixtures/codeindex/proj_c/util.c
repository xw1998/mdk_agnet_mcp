#include "inc/util.h"

static int hidden = 0;

int add(int a, int b)
{
    hidden++;
    return a + b;
}
