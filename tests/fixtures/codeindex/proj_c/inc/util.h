#ifndef INC_UTIL_H
#define INC_UTIL_H

#define LIMIT 8

typedef struct point {
    int x;
    int y;
} point_t;

int add(int a, int b);

#if LIMIT > 4
int big_only(int x);
#endif

#endif /* INC_UTIL_H */
