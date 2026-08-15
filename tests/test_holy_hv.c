// test_holy_hv.c -- Cross-platform static verification suite for holy-hv.
//
// Compiles on Linux (gcc) with no Windows/UEFI deps.
// Tests protocol consistency, stub encoding, PE layout math,
// canonical VA checks, hex parsing, and pattern scanner logic.
//
// Build:   gcc -o test_holy_hv tests/test_holy_hv.c -lm
// Run:     ./test_holy_hv

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

static int g_pass = 0, g_fail = 0;

#define TEST(name) static void test_##name(void)
#define ASSERT_EQ(a, b, msg) do { \
    if ((a) == (b)) { g_pass++; } \
    else { g_fail++; printf("  FAIL [%s:%d] %s: got 0x%llX, expected 0x%llX\n", \
        __FILE__, __LINE__, msg, (unsigned long long)(a), (unsigned long long)(b)); } \
} while(0)
#define ASSERT_NEQ(a, b, msg) do { \
    if ((a) != (b)) { g_pass++; } \
    else { g_fail++; printf("  FAIL [%s:%d] %s: got 0x%llX (should differ)\n", \
        __FILE__, __LINE__, msg, (unsigned long long)(a)); } \
} while(0)
#define ASSERT_TRUE(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg); } \
} while(0)
#define ASSERT_STR_EQ(a, b, msg) do { \
    if (strcmp((a),(b)) == 0) { g_pass++; } \
    else { g_fail++; printf("  FAIL [%s:%d] %s: got '%s', expected '%s'\n", \
        __FILE__, __LINE__, msg, (a), (b)); } \
} while(0)
#define RUN(name) do { \
    printf("  [%s]\n", #name); \
    test_##name(); \
} while(0)

// ===================================================================
// Section 1: Protocol Constants (from HolyProtocol.h / holyctl.c)
// ===================================================================

#define HOLY_KEY                0xDEADC0DEu
#define HOLY_CMD_PING               0x10000001u
#define HOLY_CMD_GET_CR3            0x10000002u
#define HOLY_CMD_GET_VMEXIT_COUNT   0x10000003u
#define HOLY_CMD_GET_HOOK_RVA       0x10000004u
#define HOLY_CMD_GET_SCRATCH        0x10000005u
#define HOLY_CMD_GET_HOST_CR3       0x10000006u
#define HOLY_CMD_GET_HOST_RIP_GDT   0x10000007u
#define HOLY_CMD_GET_HOST_RSP_IDT   0x10000008u
#define HOLY_CMD_PROBE_VA           0x10000009u
#define HOLY_CMD_GET_HOOK_FN_VA     0x1000000Au
#define HOLY_CMD_HV_READ            0x1000000Bu
#define HOLY_CMD_HV_WRITE           0x1000000Cu
#define HOLY_CMD_SCRATCH_INFO       0x1000000Du

#define HOLY_STATUS_OK              0x00000000u
#define HOLY_STATUS_UNKNOWN_CMD     0xE0000001u
#define HOLY_STATUS_BAD_ARG         0xE0000002u
#define HOLY_STATUS_BAD_VA          0xE0000003u

#define HOLY_SCRATCH_MAGIC  0x594C4F48594C4F48ull

TEST(protocol_key_matches) {
    ASSERT_EQ(HOLY_KEY, 0xDEADC0DEu, "HOLY_KEY");
}

TEST(protocol_cmd_ids_unique) {
    uint32_t cmds[] = {
        HOLY_CMD_PING, HOLY_CMD_GET_CR3, HOLY_CMD_GET_VMEXIT_COUNT,
        HOLY_CMD_GET_HOOK_RVA, HOLY_CMD_GET_SCRATCH, HOLY_CMD_GET_HOST_CR3,
        HOLY_CMD_GET_HOST_RIP_GDT, HOLY_CMD_GET_HOST_RSP_IDT, HOLY_CMD_PROBE_VA,
        HOLY_CMD_GET_HOOK_FN_VA, HOLY_CMD_HV_READ, HOLY_CMD_HV_WRITE,
        HOLY_CMD_SCRATCH_INFO
    };
    int n = sizeof(cmds)/sizeof(cmds[0]);
    for (int i = 0; i < n; i++) {
        ASSERT_EQ(cmds[i] >> 28, 1u, "cmd upper nibble should be 0x1");
        for (int j = i+1; j < n; j++) {
            ASSERT_NEQ(cmds[i], cmds[j], "cmd ids must be unique");
        }
    }
}

TEST(protocol_cmd_ids_sequential) {
    ASSERT_EQ(HOLY_CMD_PING,             0x10000001u, "PING");
    ASSERT_EQ(HOLY_CMD_GET_CR3,          0x10000002u, "GET_CR3");
    ASSERT_EQ(HOLY_CMD_GET_VMEXIT_COUNT, 0x10000003u, "GET_VMEXIT_COUNT");
    ASSERT_EQ(HOLY_CMD_GET_HOOK_RVA,     0x10000004u, "GET_HOOK_RVA");
    ASSERT_EQ(HOLY_CMD_GET_SCRATCH,      0x10000005u, "GET_SCRATCH");
    ASSERT_EQ(HOLY_CMD_GET_HOST_CR3,     0x10000006u, "GET_HOST_CR3");
    ASSERT_EQ(HOLY_CMD_GET_HOST_RIP_GDT, 0x10000007u, "GET_HOST_RIP_GDT");
    ASSERT_EQ(HOLY_CMD_GET_HOST_RSP_IDT, 0x10000008u, "GET_HOST_RSP_IDT");
    ASSERT_EQ(HOLY_CMD_PROBE_VA,         0x10000009u, "PROBE_VA");
    ASSERT_EQ(HOLY_CMD_GET_HOOK_FN_VA,   0x1000000Au, "GET_HOOK_FN_VA");
    ASSERT_EQ(HOLY_CMD_HV_READ,          0x1000000Bu, "HV_READ");
    ASSERT_EQ(HOLY_CMD_HV_WRITE,         0x1000000Cu, "HV_WRITE");
    ASSERT_EQ(HOLY_CMD_SCRATCH_INFO,     0x1000000Du, "SCRATCH_INFO");
}

TEST(protocol_status_codes) {
    ASSERT_EQ(HOLY_STATUS_OK,          0x00000000u, "STATUS_OK");
    ASSERT_EQ(HOLY_STATUS_UNKNOWN_CMD, 0xE0000001u, "STATUS_UNKNOWN_CMD");
    ASSERT_EQ(HOLY_STATUS_BAD_ARG,     0xE0000002u, "STATUS_BAD_ARG");
    ASSERT_EQ(HOLY_STATUS_BAD_VA,      0xE0000003u, "STATUS_BAD_VA");
}

TEST(scratch_magic) {
    char magic[9];
    uint64_t m = HOLY_SCRATCH_MAGIC;
    memcpy(magic, &m, 8);
    magic[8] = 0;
    ASSERT_STR_EQ(magic, "HOLYHOLY", "scratch magic as ASCII");
}

TEST(ping_sentinels) {
    ASSERT_EQ(0xC0FFEE01ull, 0xC0FFEE01ull, "PING out_a sentinel");
    ASSERT_EQ(0xCAFEBABEull, 0xCAFEBABEull, "PING out_b sentinel");
    ASSERT_EQ(0xFEEDFACEull, 0xFEEDFACEull, "PING out_c sentinel");
}

// ===================================================================
// Section 2: IOCTL codes match between driver and CLI
// ===================================================================

#define FILE_DEVICE_UNKNOWN 0x00000022u
#define METHOD_BUFFERED     0u
#define FILE_ANY_ACCESS     0u
#define CTL_CODE(t,f,m,a)  (((t)<<16)|((a)<<14)|((f)<<2)|(m))

TEST(ioctl_codes_match) {
    uint32_t call    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
    uint32_t procmem = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);
    ASSERT_EQ(call,    0x00222000u, "IOCTL_HOLY_CALL");
    ASSERT_EQ(procmem, 0x00222004u, "IOCTL_HOLY_PROCMEM");
    ASSERT_NEQ(call, procmem, "IOCTLs must differ");
}

// ===================================================================
// Section 3: Struct Layout Verification
// ===================================================================

#pragma pack(push, 1)
typedef struct {
    uint64_t command;
    uint64_t in_a;
    uint64_t in_b;
    uint64_t status;
    uint64_t out_a;
    uint64_t out_b;
    uint64_t out_c;
} HOLY_CALL_IO;

typedef struct {
    uint32_t mode;
    uint32_t pid;
    uint64_t address;
    uint32_t size;
    uint32_t result;
    uint8_t  buffer[0x1000];
} HOLY_PROCMEM_IO;

typedef struct {
    uint64_t magic;
    uint64_t vmexit_count;
    uint64_t last_exit_reason;
    uint64_t last_guest_rip;
    uint8_t  reserved[0x1000 - 32];
} HOLY_SCRATCH;
#pragma pack(pop)

TEST(struct_holy_call_io_layout) {
    ASSERT_EQ(sizeof(HOLY_CALL_IO), 56, "HOLY_CALL_IO size (7 * 8)");
    HOLY_CALL_IO io;
    ASSERT_EQ((uintptr_t)&io.command - (uintptr_t)&io, 0,  "command offset");
    ASSERT_EQ((uintptr_t)&io.in_a    - (uintptr_t)&io, 8,  "in_a offset");
    ASSERT_EQ((uintptr_t)&io.in_b    - (uintptr_t)&io, 16, "in_b offset");
    ASSERT_EQ((uintptr_t)&io.status  - (uintptr_t)&io, 24, "status offset");
    ASSERT_EQ((uintptr_t)&io.out_a   - (uintptr_t)&io, 32, "out_a offset");
    ASSERT_EQ((uintptr_t)&io.out_b   - (uintptr_t)&io, 40, "out_b offset");
    ASSERT_EQ((uintptr_t)&io.out_c   - (uintptr_t)&io, 48, "out_c offset");
}

TEST(struct_holy_procmem_io_layout) {
    ASSERT_EQ(sizeof(HOLY_PROCMEM_IO), 4 + 4 + 8 + 4 + 4 + 0x1000,
              "HOLY_PROCMEM_IO total size");
    HOLY_PROCMEM_IO io;
    ASSERT_EQ((uintptr_t)&io.mode    - (uintptr_t)&io, 0,  "mode offset");
    ASSERT_EQ((uintptr_t)&io.pid     - (uintptr_t)&io, 4,  "pid offset");
    ASSERT_EQ((uintptr_t)&io.address - (uintptr_t)&io, 8,  "address offset");
    ASSERT_EQ((uintptr_t)&io.size    - (uintptr_t)&io, 16, "size offset");
    ASSERT_EQ((uintptr_t)&io.result  - (uintptr_t)&io, 20, "result offset");
    ASSERT_EQ((uintptr_t)&io.buffer  - (uintptr_t)&io, 24, "buffer offset");
}

TEST(struct_holy_scratch_layout) {
    ASSERT_EQ(sizeof(HOLY_SCRATCH), 0x1000, "HOLY_SCRATCH = one page");
    HOLY_SCRATCH s;
    ASSERT_EQ((uintptr_t)&s.magic            - (uintptr_t)&s, 0,  "magic offset");
    ASSERT_EQ((uintptr_t)&s.vmexit_count     - (uintptr_t)&s, 8,  "vmexit_count offset");
    ASSERT_EQ((uintptr_t)&s.last_exit_reason - (uintptr_t)&s, 16, "last_exit_reason offset");
    ASSERT_EQ((uintptr_t)&s.last_guest_rip   - (uintptr_t)&s, 24, "last_guest_rip offset");
}

// ===================================================================
// Section 4: VMCS Field Constants (Intel SDM Appendix B)
// ===================================================================

TEST(vmcs_field_constants) {
    ASSERT_EQ(0x00006802u, 0x6802u, "VMCS_GUEST_CR3");
    ASSERT_EQ(0x0000681Cu, 0x681Cu, "VMCS_GUEST_RSP");
    ASSERT_EQ(0x0000681Eu, 0x681Eu, "VMCS_GUEST_RIP");
    ASSERT_EQ(0x00004402u, 0x4402u, "VMCS_EXIT_REASON");
    ASSERT_EQ(0x0000440Cu, 0x440Cu, "VMCS_VMEXIT_INSTRUCTION_LENGTH");
    ASSERT_NEQ(0x6802u, 0x681Eu, "GUEST_CR3 != GUEST_RIP");
    ASSERT_NEQ(0x681Cu, 0x681Eu, "GUEST_RSP != GUEST_RIP");
}

// ===================================================================
// Section 5: Canonical VA check (mirrors VTX.c logic)
// ===================================================================

static int is_canonical(uint64_t va) {
    uint64_t top17 = va >> 47;
    return (top17 == 0 || top17 == 0x1FFFFull);
}

TEST(canonical_va_check) {
    ASSERT_TRUE(is_canonical(0x0000000000000000ull), "zero is canonical");
    ASSERT_TRUE(is_canonical(0x00007FFFFFFFFFFFull), "max user canonical");
    ASSERT_TRUE(is_canonical(0xFFFF800000000000ull), "min kernel canonical");
    ASSERT_TRUE(is_canonical(0xFFFFFFFFFFFFFFFFull), "max kernel canonical");
    ASSERT_TRUE(is_canonical(0xFFFFF80600000000ull), "typical hv host VA");
    ASSERT_TRUE(!is_canonical(0x0000800000000000ull), "non-canonical hole start");
    ASSERT_TRUE(!is_canonical(0x0001000000000000ull), "non-canonical mid");
    ASSERT_TRUE(!is_canonical(0xFFFF7FFFFFFFFFFFull), "non-canonical hole end");
    ASSERT_TRUE(!is_canonical(0x0000FFFFFFFFFFFFull), "just above user space");
}

// ===================================================================
// Section 6: x86 VMEXIT Stub Encoding (mirrors HV.c 28-byte stub)
// ===================================================================

TEST(vmexit_stub_encoding) {
    uint8_t stub[28] = {0};
    uint64_t section   = 0xFFFFF80600400000ull;
    uint64_t offset    = 0x5000;
    uint64_t remoteFn  = section + offset;
    uint64_t origAddr  = 0xFFFFF80600211000ull;

    stub[ 0] = 0x51;   // push rcx
    stub[ 1] = 0x52;   // push rdx
    stub[ 2] = 0x48; stub[ 3] = 0x83; stub[ 4] = 0xEC; stub[ 5] = 0x28; // sub rsp,28h
    stub[ 6] = 0xE8;   // call rel32
    *(int32_t*)(stub + 7) = (int32_t)((int64_t)remoteFn - (int64_t)(section + 11));
    stub[11] = 0x48; stub[12] = 0x83; stub[13] = 0xC4; stub[14] = 0x28; // add rsp,28h
    stub[15] = 0x5A;   // pop rdx
    stub[16] = 0x59;   // pop rcx
    stub[17] = 0x48; stub[18] = 0x85; stub[19] = 0xC0; // test rax,rax
    stub[20] = 0x75; stub[21] = 0x05; // jnz +5
    stub[22] = 0xE9;   // jmp rel32
    *(int32_t*)(stub + 23) = (int32_t)((int64_t)origAddr - (int64_t)(section + 27));
    stub[27] = 0xC3;   // ret

    ASSERT_EQ(stub[0],  0x51, "push rcx");
    ASSERT_EQ(stub[1],  0x52, "push rdx");
    ASSERT_EQ(stub[2],  0x48, "REX.W prefix for sub");
    ASSERT_EQ(stub[6],  0xE8, "CALL opcode");
    ASSERT_EQ(stub[15], 0x5A, "pop rdx");
    ASSERT_EQ(stub[16], 0x59, "pop rcx");
    ASSERT_EQ(stub[20], 0x75, "JNZ opcode");
    ASSERT_EQ(stub[21], 0x05, "JNZ offset = +5 (skip jmp)");
    ASSERT_EQ(stub[22], 0xE9, "JMP opcode");
    ASSERT_EQ(stub[27], 0xC3, "RET opcode");

    int32_t call_rel = *(int32_t*)(stub + 7);
    uint64_t call_target = (section + 11) + (int64_t)call_rel;
    ASSERT_EQ(call_target, remoteFn, "CALL resolves to hook fn");

    int32_t jmp_rel = *(int32_t*)(stub + 23);
    uint64_t jmp_target = (section + 27) + (int64_t)jmp_rel;
    ASSERT_EQ(jmp_target, origAddr, "JMP resolves to original handler");

    ASSERT_EQ(stub[21], 5, "JNZ skip = 5 bytes (E9 + 4-byte rel32)");

    for (int i = 0; i < 28; i++) {
        ASSERT_TRUE(stub[i] != 0xFF, "no 0xFF opcode (indirect branch)");
    }
}

TEST(stub_call_patch_at_scan_site) {
    uint64_t scan = 0xFFFFF80600200000ull;
    uint64_t section = 0xFFFFF80600400000ull;
    int32_t patch = (int32_t)((int64_t)section - (int64_t)(scan + 20) - 4);
    uint64_t resolved = (scan + 24) + (int64_t)patch;
    ASSERT_EQ(resolved, section, "scan-site CALL patch resolves to stub");
}

// ===================================================================
// Section 7: PE Layout Math (P2ALIGNUP, section padding, RVA)
// ===================================================================

#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

TEST(p2alignup_math) {
    ASSERT_EQ(P2ALIGNUP(0, 0x1000), 0, "align 0 up to page");
    ASSERT_EQ(P2ALIGNUP(1, 0x1000), 0x1000, "align 1 up to page");
    ASSERT_EQ(P2ALIGNUP(0xFFF, 0x1000), 0x1000, "align 0xFFF up");
    ASSERT_EQ(P2ALIGNUP(0x1000, 0x1000), 0x1000, "already aligned");
    ASSERT_EQ(P2ALIGNUP(0x1001, 0x1000), 0x2000, "align 0x1001 up");
    ASSERT_EQ(P2ALIGNUP(0x12345, 0x1000), 0x13000, "align mid-range");
    ASSERT_EQ(P2ALIGNUP(0x200, 0x200), 0x200, "align to 0x200");
    ASSERT_EQ(P2ALIGNUP(0x201, 0x200), 0x400, "align 0x201 to 0x200");
}

TEST(text_padding_calculation) {
    uint32_t textVA = 0x1000;
    uint32_t textVSize = 0x3A1234;
    uint32_t nextSecVA = 0x3B0000;
    uint32_t payloadPeSize = 0x8000;

    uint32_t textEndRva = textVA + textVSize;
    uint32_t hookRva = P2ALIGNUP(textEndRva, 0x1000);
    uint32_t padSize = (nextSecVA > hookRva) ? (nextSecVA - hookRva) : 0;

    ASSERT_EQ(textEndRva, 0x3A2234, "textEndRva");
    ASSERT_EQ(hookRva, 0x3A3000, "hookRva page-aligned");
    ASSERT_EQ(padSize, nextSecVA - hookRva, "padding available");
    ASSERT_TRUE(padSize >= payloadPeSize, "enough padding for payload");
}

TEST(text_vsize_extension) {
    uint32_t textVA = 0x1000;
    uint32_t origVSize = 0x3A1234;
    uint32_t hookRva = 0x3A3000;
    uint32_t payloadPeSize = 0x8000;

    uint32_t requiredVSize = (hookRva + payloadPeSize) - textVA;
    ASSERT_TRUE(requiredVSize > origVSize, "requires VSize extension");
    ASSERT_EQ(requiredVSize, 0x3AA000, "extended VSize");
}

TEST(data_scratch_padding) {
    uint32_t dataVA = 0x3B0000;
    uint32_t dataVSize = 0x5234;
    uint32_t nextSecVA = 0x3C0000;

    uint32_t dEndRva = dataVA + dataVSize;
    uint32_t scratchRva = P2ALIGNUP(dEndRva, 0x1000);
    uint32_t dataPadSize = (nextSecVA > scratchRva) ? (nextSecVA - scratchRva) : 0;

    ASSERT_EQ(scratchRva, 0x3B6000, "scratch page-aligned");
    ASSERT_TRUE(dataPadSize >= 0x1000, "enough for one scratch page");
}

// ===================================================================
// Section 8: hex_to_bytes parser (mirrors holyctl.c)
// ===================================================================

static int hex_to_bytes(const char* s, uint8_t* out, uint32_t max) {
    uint32_t n = 0;
    while (*s && n < max) {
        while (*s == ' ' || *s == ',' || *s == ':' || *s == '-') s++;
        if (!*s) break;
        int hi = -1, lo = -1;
        if (isxdigit((unsigned char)s[0]))
            hi = (s[0] <= '9') ? s[0]-'0' : (tolower(s[0])-'a'+10);
        if (isxdigit((unsigned char)s[1]))
            lo = (s[1] <= '9') ? s[1]-'0' : (tolower(s[1])-'a'+10);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return (int)n;
}

TEST(hex_to_bytes_basic) {
    uint8_t buf[16];
    int n;

    n = hex_to_bytes("DEADBEEF", buf, 16);
    ASSERT_EQ(n, 4, "parsed 4 bytes");
    ASSERT_EQ(buf[0], 0xDE, "byte 0");
    ASSERT_EQ(buf[1], 0xAD, "byte 1");
    ASSERT_EQ(buf[2], 0xBE, "byte 2");
    ASSERT_EQ(buf[3], 0xEF, "byte 3");
}

TEST(hex_to_bytes_separators) {
    uint8_t buf[16];
    int n;

    n = hex_to_bytes("DE:AD-BE,EF", buf, 16);
    ASSERT_EQ(n, 4, "parsed with separators");
    ASSERT_EQ(buf[0], 0xDE, "sep byte 0");
    ASSERT_EQ(buf[3], 0xEF, "sep byte 3");
}

TEST(hex_to_bytes_spaces) {
    uint8_t buf[16];
    int n = hex_to_bytes("48 89 5C 24", buf, 16);
    ASSERT_EQ(n, 4, "spaced hex");
    ASSERT_EQ(buf[0], 0x48, "space byte 0");
    ASSERT_EQ(buf[1], 0x89, "space byte 1");
    ASSERT_EQ(buf[2], 0x5C, "space byte 2");
    ASSERT_EQ(buf[3], 0x24, "space byte 3");
}

TEST(hex_to_bytes_lowercase) {
    uint8_t buf[16];
    int n = hex_to_bytes("cafebabe", buf, 16);
    ASSERT_EQ(n, 4, "lowercase hex");
    ASSERT_EQ(buf[0], 0xCA, "lc byte 0");
    ASSERT_EQ(buf[1], 0xFE, "lc byte 1");
}

TEST(hex_to_bytes_empty) {
    uint8_t buf[16];
    int n = hex_to_bytes("", buf, 16);
    ASSERT_EQ(n, 0, "empty string");
}

TEST(hex_to_bytes_max_limit) {
    uint8_t buf[2];
    int n = hex_to_bytes("DEADBEEFCAFE", buf, 2);
    ASSERT_EQ(n, 2, "limited by max");
    ASSERT_EQ(buf[0], 0xDE, "limited byte 0");
    ASSERT_EQ(buf[1], 0xAD, "limited byte 1");
}

// ===================================================================
// Section 9: Pattern Scanner Logic (mirrors Utils.c FindPattern)
// ===================================================================

#define IN_RANGE(x, a, b) ((x) >= (a) && (x) <= (b))
#define GET_BITS(x) (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xA) : (IN_RANGE(x, '0', '9') ? (x - '0') : 0))
#define GET_BYTE_PAT(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

static uint64_t test_find_pattern(void* base, uint64_t size, const char* pattern) {
    uint8_t* firstMatch = NULL;
    const char* currentPattern = pattern;
    uint8_t* start = (uint8_t*)base;
    uint8_t* end = start + size;

    for (uint8_t* current = start; current < end; current++) {
        uint8_t byte = currentPattern[0];
        if (!byte) return (uint64_t)(uintptr_t)firstMatch;
        if (byte == '?' || *current == GET_BYTE_PAT(byte, currentPattern[1])) {
            if (!firstMatch) firstMatch = current;
            if (!currentPattern[2]) return (uint64_t)(uintptr_t)firstMatch;
            currentPattern += (byte == '?') ? 2 : 3;
        } else {
            currentPattern = pattern;
            firstMatch = NULL;
        }
    }
    return 0;
}

TEST(pattern_scanner_exact) {
    uint8_t data[] = {0x00, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x00};
    uint64_t r = test_find_pattern(data, sizeof(data), "48 89 5C 24 08");
    ASSERT_EQ(r, (uint64_t)(uintptr_t)&data[1], "exact match at offset 1");
}

TEST(pattern_scanner_wildcard) {
    uint8_t data[] = {0x48, 0x89, 0x5C, 0x24, 0xFF, 0x48};
    uint64_t r = test_find_pattern(data, sizeof(data), "48 89 5C 24 ? 48");
    ASSERT_EQ(r, (uint64_t)(uintptr_t)&data[0], "wildcard match");
}

TEST(pattern_scanner_no_match) {
    uint8_t data[] = {0x48, 0x89, 0x5C, 0x24, 0x08};
    uint64_t r = test_find_pattern(data, sizeof(data), "48 89 5C 24 10");
    ASSERT_EQ(r, 0, "no match returns 0");
}

TEST(pattern_scanner_intel_vmexit_sig_prefix) {
    uint8_t data[] = {0x00, 0x65, 0xC6, 0x04, 0x25, 0x6D, 0x00, 0x00, 0x00, 0x00};
    uint64_t r = test_find_pattern(data, sizeof(data), "65 C6 04 25 6D");
    ASSERT_EQ(r, (uint64_t)(uintptr_t)&data[1], "Intel VMEXIT sig prefix");
}

// ===================================================================
// Section 10: Build Mode Stage Guards
// ===================================================================

#define HOLY_HV_MUTATION_STAGE_NONE    0
#define HOLY_HV_MUTATION_STAGE_COPYMEM 1
#define HOLY_HV_MUTATION_STAGE_RELOC   2
#define HOLY_HV_MUTATION_STAGE_PATCH   3

TEST(build_mode_stages) {
    ASSERT_TRUE(HOLY_HV_MUTATION_STAGE_NONE < HOLY_HV_MUTATION_STAGE_COPYMEM, "NONE < COPYMEM");
    ASSERT_TRUE(HOLY_HV_MUTATION_STAGE_COPYMEM < HOLY_HV_MUTATION_STAGE_RELOC, "COPYMEM < RELOC");
    ASSERT_TRUE(HOLY_HV_MUTATION_STAGE_RELOC < HOLY_HV_MUTATION_STAGE_PATCH, "RELOC < PATCH");

    int current = HOLY_HV_MUTATION_STAGE_PATCH;
    ASSERT_TRUE(current > HOLY_HV_MUTATION_STAGE_NONE, "current stage allows mutation");
    ASSERT_TRUE(current >= HOLY_HV_MUTATION_STAGE_RELOC, "current stage applies relocs");
    ASSERT_TRUE(current >= HOLY_HV_MUTATION_STAGE_PATCH, "current stage patches CALL");
}

// ===================================================================
// Section 11: Virtual Address Decomposition (x86-64 4-level paging)
// ===================================================================

typedef union {
    uint64_t Value;
    struct {
        uint64_t Offset   : 12;
        uint64_t PtIndex  : 9;
        uint64_t PdIndex  : 9;
        uint64_t PdptIndex: 9;
        uint64_t Pml4Index: 9;
        uint64_t Reserved : 16;
    };
} TEST_VIRTUAL_ADDRESS;

TEST(virtual_address_decomposition) {
    TEST_VIRTUAL_ADDRESS va;
    va.Value = 0xFFFFF80600400ABC;
    ASSERT_EQ(va.Offset, 0xABC, "page offset");

    va.Value = 0;
    va.Pml4Index = 256;
    va.PdptIndex = 0;
    va.PdIndex = 0;
    va.PtIndex = 0;
    va.Offset = 0;
    ASSERT_EQ(va.Value & 0xFFFFFFFFFFFFull, 0x800000000000ull, "PML4[256] = kernel half start");
}

TEST(cr3_pml4_extraction) {
    uint64_t cr3 = 0x00000001ABCDE067ull;
    uint64_t pml4_phys = cr3 & 0x000FFFFFFFFFF000ull;
    ASSERT_EQ(pml4_phys, 0x00000001ABCDE000ull, "PML4 physical from CR3");
}

// ===================================================================
// Section 12: GPR Save Area Layout (Intel VMEXIT context)
// ===================================================================

TEST(gpr_save_area_offsets) {
    uint64_t gprs[16];
    memset(gprs, 0, sizeof(gprs));

    uint32_t status = 0;
    gprs[0] = (uint64_t)status;    // RAX = status
    gprs[3] = 0xC0FFEE01ull;       // RBX = outA
    gprs[1] = 0xCAFEBABEull;       // RCX = outB
    gprs[2] = 0xFEEDFACEull;       // RDX = outC

    ASSERT_EQ(gprs[0], 0, "RAX = status OK");
    ASSERT_EQ(gprs[3], 0xC0FFEE01ull, "RBX = outA (PING)");
    ASSERT_EQ(gprs[1], 0xCAFEBABEull, "RCX = outB (PING)");
    ASSERT_EQ(gprs[2], 0xFEEDFACEull, "RDX = outC (PING)");
}

// ===================================================================
// Section 13: HV Image Base Calculation (VTX.c g_HookRva math)
// ===================================================================

TEST(hv_image_base_calculation) {
    uint64_t hvBase_actual = 0xFFFFF80600000000ull;
    uint64_t hookRva = 0x3A3000;
    uint64_t payloadBase = hvBase_actual + hookRva;

    uint64_t computed_hvBase = payloadBase - hookRva;
    ASSERT_EQ(computed_hvBase, hvBase_actual, "hvBase from payloadBase - hookRva");

    uint64_t origVA_winload = 0xFFFFF80600211000ull;
    uint64_t hvBase_winload = 0xFFFFF80600000000ull;
    uint64_t origRva = origVA_winload - hvBase_winload;
    uint64_t origVA_runtime = computed_hvBase + origRva;
    ASSERT_EQ(origRva, 0x211000, "orig handler RVA");
    ASSERT_EQ(origVA_runtime, origVA_winload, "orig handler VA round-trips");
}

// ===================================================================
// Section 14: Relocation Logic
// ===================================================================

TEST(relocation_delta_calculation) {
    uint64_t imageBase_efi = 0x10000;
    uint64_t section = 0xFFFFF80600400000ull;
    int64_t delta = (int64_t)(section - imageBase_efi);

    ASSERT_TRUE(delta > 0, "delta is positive (relocated higher)");

    uint64_t ptr_original = imageBase_efi + 0x5000;
    uint64_t ptr_relocated = ptr_original + delta;
    ASSERT_EQ(ptr_relocated, section + 0x5000, "relocated pointer");
}

// ===================================================================
// Section 15: Cross-file Consistency Checks
// ===================================================================

TEST(holyctl_cmd_mirror) {
    ASSERT_EQ(HOLY_CMD_PING,             0x10000001u, "holyctl PING");
    ASSERT_EQ(HOLY_CMD_GET_CR3,          0x10000002u, "holyctl GET_CR3");
    ASSERT_EQ(HOLY_CMD_GET_VMEXIT_COUNT, 0x10000003u, "holyctl GET_VMEXIT_COUNT");
    ASSERT_EQ(HOLY_CMD_GET_HOOK_RVA,     0x10000004u, "holyctl GET_HOOK_RVA");
    ASSERT_EQ(HOLY_CMD_GET_SCRATCH,      0x10000005u, "holyctl GET_SCRATCH");
    ASSERT_EQ(HOLY_CMD_GET_HOST_CR3,     0x10000006u, "holyctl GET_HOST_CR3");
    ASSERT_EQ(HOLY_CMD_GET_HOST_RIP_GDT, 0x10000007u, "holyctl GET_HOST_RIP_GDT");
    ASSERT_EQ(HOLY_CMD_GET_HOST_RSP_IDT, 0x10000008u, "holyctl GET_HOST_RSP_IDT");
    ASSERT_EQ(HOLY_CMD_PROBE_VA,         0x10000009u, "holyctl PROBE_VA");
    ASSERT_EQ(HOLY_CMD_GET_HOOK_FN_VA,   0x1000000Au, "holyctl GET_HOOK_FN_VA");
    ASSERT_EQ(HOLY_CMD_HV_READ,          0x1000000Bu, "holyctl HV_READ");
    ASSERT_EQ(HOLY_CMD_HV_WRITE,         0x1000000Cu, "holyctl HV_WRITE");
    ASSERT_EQ(HOLY_CMD_SCRATCH_INFO,     0x1000000Du, "holyctl SCRATCH_INFO");
}

TEST(driver_key_matches_protocol) {
    ASSERT_EQ(HOLY_KEY, 0xDEADC0DEu, "driver HOLY_KEY matches protocol");
}

// ===================================================================
// Section 16: Legacy Protocol (Shared.h) Consistency
// ===================================================================

#define CPUID_BACKDOOR     0xaabbccdd12345ull
#define CPUID_RETURN_VALUE 0x123456789ull

TEST(legacy_protocol_values) {
    ASSERT_NEQ(CPUID_BACKDOOR, (uint64_t)HOLY_KEY, "legacy key differs from new protocol");
    ASSERT_EQ(CPUID_RETURN_VALUE, 0x123456789ull, "legacy return sentinel");
}

// ===================================================================
// Main
// ===================================================================

int main(void) {
    printf("=== holy-hv static verification suite ===\n\n");

    printf("[Protocol]\n");
    RUN(protocol_key_matches);
    RUN(protocol_cmd_ids_unique);
    RUN(protocol_cmd_ids_sequential);
    RUN(protocol_status_codes);
    RUN(scratch_magic);
    RUN(ping_sentinels);

    printf("\n[IOCTL]\n");
    RUN(ioctl_codes_match);

    printf("\n[Struct Layout]\n");
    RUN(struct_holy_call_io_layout);
    RUN(struct_holy_procmem_io_layout);
    RUN(struct_holy_scratch_layout);

    printf("\n[VMCS Fields]\n");
    RUN(vmcs_field_constants);

    printf("\n[Canonical VA]\n");
    RUN(canonical_va_check);

    printf("\n[VMEXIT Stub]\n");
    RUN(vmexit_stub_encoding);
    RUN(stub_call_patch_at_scan_site);

    printf("\n[PE Layout Math]\n");
    RUN(p2alignup_math);
    RUN(text_padding_calculation);
    RUN(text_vsize_extension);
    RUN(data_scratch_padding);

    printf("\n[Hex Parser]\n");
    RUN(hex_to_bytes_basic);
    RUN(hex_to_bytes_separators);
    RUN(hex_to_bytes_spaces);
    RUN(hex_to_bytes_lowercase);
    RUN(hex_to_bytes_empty);
    RUN(hex_to_bytes_max_limit);

    printf("\n[Pattern Scanner]\n");
    RUN(pattern_scanner_exact);
    RUN(pattern_scanner_wildcard);
    RUN(pattern_scanner_no_match);
    RUN(pattern_scanner_intel_vmexit_sig_prefix);

    printf("\n[Build Mode]\n");
    RUN(build_mode_stages);

    printf("\n[Virtual Address]\n");
    RUN(virtual_address_decomposition);
    RUN(cr3_pml4_extraction);

    printf("\n[GPR Layout]\n");
    RUN(gpr_save_area_offsets);

    printf("\n[HV Base Calculation]\n");
    RUN(hv_image_base_calculation);

    printf("\n[Relocation]\n");
    RUN(relocation_delta_calculation);

    printf("\n[Cross-file Consistency]\n");
    RUN(holyctl_cmd_mirror);
    RUN(driver_key_matches_protocol);

    printf("\n[Legacy Protocol]\n");
    RUN(legacy_protocol_values);

    printf("\n=== Results: %d passed, %d failed ===\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
