/* audit_record: the function that disappears in v2 and comes back in v3 (own translation unit,
 * so the v3 "recompiled" variant can change only its code generation). */
#define NOINLINE __attribute__((noinline))
typedef unsigned int u32;
extern volatile u32 g_audit[64];
u32 fold(u32 x);

NOINLINE u32 audit_record(u32 code, u32 detail) {
    u32 h = 0xA5C3u ^ code;
    for (u32 i = 0; i < 16; i++) {
        h = fold(h + detail * 0x9E3779B9u + i);
        if (h & 0x1F2Eu) h ^= 0x00C0FFEEu;
        g_audit[(h + i) & 63] = h ^ (code << 3);
    }
    return h ^ 0x5EEDu;
}
