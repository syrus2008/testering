/* ACET resurrection corpus — core module (original code, same license as ACET).
 * Freestanding x64 PE DLL. SCEN selects the variant (see ../build.py):
 *   1 = v1 (audit_record present), 2 = v2 (audit_record absent),
 *   3 = v3 identical / recompiled (audit_record back), 4 = v3 lookalike (trace_record, not audit_record).
 */
#define NOINLINE __attribute__((noinline))
#define EXPORT __declspec(dllexport)
typedef unsigned int u32;
typedef unsigned char u8;

EXPORT volatile u32 g_audit[64];
EXPORT volatile u32 g_trace[64];
EXPORT volatile u32 g_stats[8];

NOINLINE u32 fold(u32 x) {
    x ^= x >> 13;
    x *= 0x85EBCA6Bu;
    x ^= x >> 16;
    return x;
}

NOINLINE u32 sum_bytes(const u8 *p, u32 n) {
    u32 s = 0;
    for (u32 i = 0; i < n; i++) s += p[i];
    return s;
}

#if SCEN == 1 || SCEN == 3
u32 audit_record(u32 code, u32 detail);
#endif
#if SCEN == 4
u32 trace_record(u32 code, u32 detail);
#endif

EXPORT u32 Run(const u8 *p, u32 n) {
    u32 s = sum_bytes(p, n);
#if SCEN == 1 || SCEN == 3
    s += audit_record(s, n);
#endif
    return fold(s);
}

#if SCEN >= 3
/* unrelated change so that every v3 differs from v1 as a whole binary */
EXPORT u32 StatsTick(u32 k) {
    g_stats[k & 7] += fold(k) & 0xFFu;
    return g_stats[k & 7];
}
#endif

#if SCEN == 4
EXPORT u32 Flush(u32 k) { return trace_record(k, k >> 4); }
#endif

int _DllMainCRTStartup(void *h, u32 reason, void *r) { (void)h; (void)r; return reason != 0xFFFFFFFFu; }
