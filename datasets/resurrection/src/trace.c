/* trace_record: a different function that resembles audit_record (same loop shape and callee,
 * different constants, caller and purpose). It must never be taken for a resurrection. */
#define NOINLINE __attribute__((noinline))
typedef unsigned int u32;
extern volatile u32 g_trace[64];
u32 fold(u32 x);

NOINLINE u32 trace_record(u32 code, u32 detail) {
    u32 h = 0x3C5Au ^ code;
    for (u32 i = 0; i < 16; i++) {
        h = fold(h + detail * 0x7F4A7C15u + i);
        if (h & 0x2E1Fu) h ^= 0x00BADF00u;
        g_trace[(h + i) & 63] = h ^ (code << 3);
    }
    return h ^ 0x7ACEu;
}
