struct pt { int x; unsigned short y; char z[8]; int w; };
volatile int arr[16];
volatile int g_cnt = 3;
volatile unsigned g_bits = 0x12345678;
volatile unsigned g_wide;
volatile int g_signed = -7;

int dispatch(int op, int a, int b) {
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return a & b;
    case 4: return a | b;
    case 5: return a ^ b;
    case 6: return a << 1;
    case 7: return a >> 1;
    default: return -1;
    }
}

int use_struct(struct pt *p) {
    p->x = 1; p->y = 2; p->z[3] = 'a';
    p->w = p->x + p->y;
    return p->w;
}

int sum_arr(int n) {
    int s = 0; int i;
    for (i = 0; i < n; i++) s += arr[i];
    return s;
}

int it_block(int a, int b) {
    int r = a;
    if (a & 1) r = -b;
    if (a & 2) r = r + 3;
    else r = r - 5;
    return r;
}

unsigned field_stuff(unsigned v) {
    unsigned lo = (v >> 5) & 0x1FF;      /* ubfx */
    int sg = (int)(v << 12) >> 20;       /* sbfx */
    return lo + (unsigned)sg;
}

int mac(int a, int b, int c) {
    return a + b * c;                    /* mla */
}

unsigned swap32(unsigned v) {
    return ((v & 0xFF) << 24) | ((v >> 8 & 0xFF) << 16) |
           ((v >> 16 & 0xFF) << 8) | (v >> 24);   /* rev */
}

unsigned long long wide_mul(unsigned long long a, unsigned b) {
    return a * (unsigned long long)b;    /* umull / umlal */
}

int while_loop(int n) {
    int s = 0;
    while (n > 0) { s += n; n--; }
    return s;
}

int divmod(int a, int b) {
    if (b == 0) return 0;
    return a / b + a % b;
}

int sparse_switch(int op) {
    switch (op) {
    case 1: return 10;
    case 9: return 20;
    case 40: return 30;
    default: return 0;
    }
}

unsigned revbytes(unsigned v) {
    return __rev(v);                     /* rev */
}

int carry_flags(int a, int b) {
    unsigned t = (unsigned)a * (unsigned)b;
    if ((unsigned)a > 0xFFFFu) return (int)(t >> 16);
    return (int)(t & 0xFFFF);
}
