/* ACET demo dataset — "Fictional Guard" service executable. Freestanding; never executed by ACET. */
#define NOINLINE __attribute__((noinline))
typedef unsigned int u32;

static volatile u32 g_ticks;

NOINLINE u32 parse_args(const char *cmd) {
    u32 flags = 0;
    for (u32 i = 0; cmd[i]; i++) {
        if (cmd[i] == '-' && cmd[i + 1] == 'v') flags |= 1;
        if (cmd[i] == '-' && cmd[i + 1] == 'q') flags |= 2;
#if VERSION >= 2
        if (cmd[i] == '-' && cmd[i + 1] == 's') flags |= 4;
#endif
    }
    return flags;
}

NOINLINE u32 compute_token(u32 seed) {
    u32 t = seed * 2654435761u;
    for (int r = 0; r < 5; r++) t = (t << 7 | t >> 25) ^ 0x9E3779B9u;
    return t;
}

NOINLINE u32 schedule_loop(u32 rounds) {
    u32 acc = 0;
    for (u32 i = 0; i < rounds; i++) {
        g_ticks++;
        acc += compute_token(i) & 0xFF;
#if VERSION >= 3
        if (acc > 5000) break;
#endif
    }
    return acc;
}

int mainCRTStartup(void) {
    u32 f = parse_args("-v -q");
    return (int)schedule_loop(16 + f);
}
