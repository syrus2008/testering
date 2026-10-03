/* ACET demo dataset — "Fictional Guard" core module.
 * Original code written for ACET's golden tests (license: same as ACET). Freestanding, no CRT.
 * VERSION selects the variant: 1, 2 or 3. Changes between versions are documented in ../GROUND_TRUTH.md.
 */
#define NOINLINE __attribute__((noinline))
#define EXPORT __declspec(dllexport)
typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

static u8 g_ring[256];
static u32 g_ring_pos;
static u32 g_state;
static const char *g_sigs[] = {"FGRD", "HOOK", "PTCH", "INJT"};

NOINLINE u32 mem_compare(const u8 *a, const u8 *b, u32 n) {
    for (u32 i = 0; i < n; i++) {
        if (a[i] != b[i]) return (u32)(a[i] - b[i]) | 1u;
    }
    return 0;
}

NOINLINE void mem_copy(u8 *d, const u8 *s, u32 n) {
    for (u32 i = 0; i < n; i++) d[i] = s[i];
}

NOINLINE u32 str_len(const char *s) {
    u32 n = 0;
    while (s[n]) n++;
    return n;
}

NOINLINE u32 checksum32(const u8 *buf, u32 len) {
#if VERSION == 1
    u32 a = 1, b = 0;
    for (u32 i = 0; i < len; i++) { a = (a + buf[i]) % 65521u; b = (b + a) % 65521u; }
    return (b << 16) | a;
#else
    u32 a = 7, b = 3;
    for (u32 i = 0; i < len; i++) { a = (a + buf[i] * 3u) % 65519u; b = (b ^ a) + (a >> 3); }
    return (b << 15) ^ a;
#endif
}

NOINLINE u32 crc32(const u8 *buf, u32 len) {
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

#if VERSION == 1
NOINLINE void xor_obfuscate(u8 *buf, u32 len, u32 key) {
#else
NOINLINE void obfuscate_buffer(u8 *buf, u32 len, u32 key) { /* renamed, same body */
#endif
    for (u32 i = 0; i < len; i++) {
        buf[i] ^= (u8)(key >> ((i & 3) * 8));
        key = key * 1103515245u + 12345u;
    }
}

#if VERSION == 1
NOINLINE u32 parse_config(const char *s) {
    u32 entries = 0, i = 0;
    while (s[i]) {
        u32 start = i, has_eq = 0;
        while (s[i] && s[i] != '\n') { if (s[i] == '=') has_eq = 1; i++; }
        if (has_eq && i > start + 2) entries++;
        if (s[i] == '\n') i++;
        if (s[i] == '#') { while (s[i] && s[i] != '\n') i++; }
    }
    return entries;
}
#else
/* parse_config split into parse_line + parse_config (SPLIT) */
NOINLINE u32 parse_line(const char *s, u32 *i) {
    u32 start = *i, has_eq = 0;
    while (s[*i] && s[*i] != '\n') { if (s[*i] == '=') has_eq = 1; (*i)++; }
    return has_eq && *i > start + 2;
}
NOINLINE u32 parse_config(const char *s) {
    u32 entries = 0, i = 0;
    while (s[i]) {
        entries += parse_line(s, &i);
        if (s[i] == '\n') i++;
        if (s[i] == '#') { while (s[i] && s[i] != '\n') i++; }
    }
    return entries;
}
#endif

#if VERSION == 1
NOINLINE u32 check_magic(const u8 *buf) {
    return buf[0] == 'F' && buf[1] == 'G' && buf[2] == 'R' && buf[3] == 'D';
}
NOINLINE u32 validate_header(const u8 *buf, u32 len) {
    if (len < 16) return 0;
    u32 declared = buf[4] | (buf[5] << 8) | (buf[6] << 16) | ((u32)buf[7] << 24);
    if (declared > len) return 0;
    u32 version = buf[8];
    return version >= 1 && version <= 4;
}
#else
/* check_magic + validate_header merged (MERGE) */
NOINLINE u32 validate_header_full(const u8 *buf, u32 len) {
    if (len < 16) return 0;
    if (!(buf[0] == 'F' && buf[1] == 'G' && buf[2] == 'R' && buf[3] == 'D')) return 0;
    u32 declared = buf[4] | (buf[5] << 8) | (buf[6] << 16) | ((u32)buf[7] << 24);
    if (declared > len) return 0;
    u32 version = buf[8];
    return version >= 1 && version <= 5;
}
#endif

NOINLINE u32 scan_signatures(const u8 *buf, u32 len) {
    u32 hits = 0;
    for (u32 s = 0; s < sizeof(g_sigs) / sizeof(g_sigs[0]); s++) {
        u32 n = str_len(g_sigs[s]);
        for (u32 i = 0; i + n <= len; i++) {
            if (mem_compare(buf + i, (const u8 *)g_sigs[s], n) == 0) hits++;
        }
    }
    return hits;
}

NOINLINE u32 heartbeat_tick(u32 state) {
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    g_state = state;
    return state;
}

NOINLINE u32 policy_decide(u32 score) {
#if VERSION < 3
    switch (score / 10) {
    case 0: return 0;
    case 1: case 2: return 1;
    case 3: case 4: case 5: return 2;
    default: return score > 90 ? 4 : 3;
    }
#else
    if (score < 5) return 0;
    if (score < 25) return 1;
    if (score < 60) return 2 + (score & 1);
    return score > 95 ? 5 : 4;
#endif
}

#if VERSION != 2
/* report_event disappears in v2 and comes back (identical) in v3 (RESURRECTED) */
NOINLINE void report_event(u32 code, u32 detail) {
    u8 rec[8];
    rec[0] = (u8)code; rec[1] = (u8)(code >> 8); rec[2] = (u8)detail; rec[3] = (u8)(detail >> 8);
    rec[4] = (u8)g_state; rec[5] = 0xAC; rec[6] = 0xE7; rec[7] = (u8)(g_ring_pos >> 3);
    for (u32 i = 0; i < 8; i++) g_ring[(g_ring_pos + i) & 255] = rec[i];
    g_ring_pos = (g_ring_pos + 8) & 255;
}
#endif

#if VERSION >= 2
/* new in v2 */
NOINLINE u32 integrity_probe(const u8 *code, u32 len, u32 expected) {
    u32 c = crc32(code, len);
    u32 k = checksum32(code, len);
    return (c ^ k) == expected ? 1u : 0u;
}
#endif

#if VERSION >= 3
/* new in v3 */
NOINLINE u32 telemetry_flush(u8 *out, u32 cap) {
    u32 n = g_ring_pos < cap ? g_ring_pos : cap;
    mem_copy(out, g_ring, n);
    for (u32 i = 0; i < 256; i++) g_ring[i] = 0;
    g_ring_pos = 0;
    return n;
}
#endif

EXPORT u32 GuardInit(const char *config) {
    g_state = 0x12345678u;
    return parse_config(config);
}

EXPORT u32 GuardScan(u8 *buf, u32 len) {
#if VERSION == 1
    if (!check_magic(buf) || !validate_header(buf, len)) return 0xFFFFFFFFu;
#else
    if (!validate_header_full(buf, len)) return 0xFFFFFFFFu;
#endif
    u32 hits = scan_signatures(buf, len);
    u32 sum = checksum32(buf, len) ^ crc32(buf, len);
#if VERSION == 1
    xor_obfuscate(buf, len, sum);
#else
    obfuscate_buffer(buf, len, sum);
#endif
#if VERSION != 2
    report_event(1, hits);
#endif
#if VERSION >= 2
    if (!integrity_probe(buf, len, sum)) hits += 100;
#endif
    return policy_decide(hits);
}

EXPORT u32 GuardTick(u8 *out, u32 cap) {
    u32 s = heartbeat_tick(g_state);
#if VERSION >= 3
    return telemetry_flush(out, cap) + (s & 1);
#else
    (void)out; (void)cap;
    return s;
#endif
}

int __stdcall _DllMainCRTStartup(void *h, u32 reason, void *r) { (void)h; (void)reason; (void)r; return 1; }
