// holyctl.exe -- user-mode CLI for the HolyHvProbe driver + EFI hook.
//
// Hv-side commands (CPUID with HOLY_KEY in RCX, RAX = command):
//   ping       round-trip sentinels through the hv hook
//   cr3        guest CR3 at exit time
//   rva        address of the original hv VMEXIT handler
//   scratch    address + size of our hv .data scratch page
//   count      total VMEXITs we've intercepted + last exit reason + last RIP
//   raw <hex>  send arbitrary command id, dump raw output
//
// Process-memory commands (kernel driver attach + ProbeFor/RtlCopy):
//   read  <pid> <hex_addr> <size>
//   write <pid> <hex_addr> <hex_bytes>
//   scan  <pid> <hex_addr> <size> <hex_or_string_pattern>
//   patch <pid> <hex_addr> <hex_bytes>       (alias for write)

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define IOCTL_HOLY_CALL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOLY_PROCMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
#define HOLY_STATUS_BAD_VA          0xE0000003u

#define HOLY_PROC_READ   0u
#define HOLY_PROC_WRITE  1u
#define HOLY_PROC_BUFSZ  0x1000u

typedef struct {
    UINT64 command;
    UINT64 in_a;
    UINT64 in_b;
    UINT64 status;
    UINT64 out_a;
    UINT64 out_b;
    UINT64 out_c;
} HOLY_CALL_IO;

#pragma pack(push, 1)
typedef struct {
    UINT32 mode;
    UINT32 pid;
    UINT64 address;
    UINT32 size;
    UINT32 result;
    UINT8  buffer[HOLY_PROC_BUFSZ];
} HOLY_PROCMEM_IO;
#pragma pack(pop)

static HANDLE open_device(void) {
    HANDLE h = CreateFileA("\\\\.\\HolyHvProbe",
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "holyctl: cannot open \\\\.\\HolyHvProbe (err %lu)\n",
                GetLastError());
        fprintf(stderr, "         driver not loaded? -- `sc start HolyHvProbe`\n");
    }
    return h;
}

static int hv_call(UINT32 cmd, HOLY_CALL_IO* io) {
    HANDLE h = open_device();
    if (h == INVALID_HANDLE_VALUE) return -1;
    memset(io, 0, sizeof(*io));
    io->command = cmd;
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_HOLY_CALL,
                              io, sizeof(*io), io, sizeof(*io), &bytes, NULL);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (!ok) {
        fprintf(stderr, "holyctl: hv IOCTL failed (err %lu)\n", err);
        return -1;
    }
    return 0;
}

static int proc_call(UINT32 mode, UINT32 pid, UINT64 addr,
                     UINT8* buf, UINT32 size)
{
    if (size == 0 || size > HOLY_PROC_BUFSZ) {
        fprintf(stderr, "holyctl: size must be 1..%u\n", HOLY_PROC_BUFSZ);
        return -1;
    }
    HANDLE h = open_device();
    if (h == INVALID_HANDLE_VALUE) return -1;
    HOLY_PROCMEM_IO io = {0};
    io.mode    = mode;
    io.pid     = pid;
    io.address = addr;
    io.size    = size;
    if (mode == HOLY_PROC_WRITE) memcpy(io.buffer, buf, size);
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_HOLY_PROCMEM,
                              &io, sizeof(io), &io, sizeof(io), &bytes, NULL);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (!ok) {
        fprintf(stderr, "holyctl: procmem IOCTL failed (err %lu)\n", err);
        return -1;
    }
    if (io.result != 0) {
        fprintf(stderr, "holyctl: target op failed (NTSTATUS 0x%08X)\n", io.result);
        return -1;
    }
    if (mode == HOLY_PROC_READ) memcpy(buf, io.buffer, size);
    return 0;
}

// --- hex helpers ---------------------------------------------------------

static int hex_to_bytes(const char* s, UINT8* out, UINT32 max) {
    UINT32 n = 0;
    while (*s && n < max) {
        while (*s == ' ' || *s == ',' || *s == ':' || *s == '-') s++;
        if (!*s) break;
        int hi = -1, lo = -1;
        if (isxdigit((unsigned char)s[0])) hi = (s[0] <= '9') ? s[0]-'0' : (tolower(s[0])-'a'+10);
        if (isxdigit((unsigned char)s[1])) lo = (s[1] <= '9') ? s[1]-'0' : (tolower(s[1])-'a'+10);
        if (hi < 0 || lo < 0) break;
        out[n++] = (UINT8)((hi << 4) | lo);
        s += 2;
    }
    return (int)n;
}

static void hex_dump(UINT64 base, const UINT8* p, UINT32 n) {
    for (UINT32 i = 0; i < n; i += 16) {
        printf("%016llX  ", base + i);
        UINT32 row = (n - i < 16) ? (n - i) : 16;
        for (UINT32 j = 0; j < 16; j++) {
            if (j < row) printf("%02X ", p[i+j]); else printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" ");
        for (UINT32 j = 0; j < row; j++) {
            UINT8 c = p[i+j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("\n");
    }
}

// --- subcommands ---------------------------------------------------------

static int cmd_ping(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_PING, &io)) return 1;
    int ok = io.status == HOLY_STATUS_OK
          && io.out_a == 0xC0FFEE01ull
          && io.out_b == 0xCAFEBABEull
          && io.out_c == 0xFEEDFACEull;
    printf("status=%016llX  RBX=%016llX RCX=%016llX RDX=%016llX  %s\n",
           io.status, io.out_a, io.out_b, io.out_c,
           ok ? "hook is live" : "PING did NOT round-trip");
    return ok ? 0 : 2;
}

static int cmd_cr3(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_CR3, &io)) return 1;
    printf("guest CR3 = 0x%016llX\n", io.out_a);
    return 0;
}

static int cmd_rva(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_HOOK_RVA, &io)) return 1;
    printf("OriginalVmExitHandlerIntelAddr = 0x%016llX\n", io.out_a);
    return 0;
}

static int cmd_scratch(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_SCRATCH, &io)) return 1;
    printf("scratch base = 0x%016llX  size = 0x%llX  magic = 0x%016llX\n",
           io.out_a, io.out_b, io.out_c);
    if (io.out_c == 0x594C4F48594C4F48ull) printf("  magic OK -- hook is writing scratch\n");
    else if (io.out_a == 0)                printf("  scratch is disabled (no .data padding?)\n");
    else                                   printf("  magic missing -- first call did not bookkeep\n");
    return 0;
}

static int cmd_host_cr3(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_HOST_CR3, &io)) return 1;
    UINT64 cr3 = io.out_a;
    UINT64 origVa = io.out_b;
    UINT64 hookOffset = io.out_c;
    printf("host CR3 (PML4 phys) = 0x%016llX  (raw=0x%016llX)\n",
           cr3 & 0x000FFFFFFFFFF000ull, cr3);
    printf("orig handler VA      = 0x%016llX\n", origVa);
    printf("hookRva offset       = 0x%llX\n", hookOffset);
    if (origVa && cr3) {
        UINT64 imageBaseVa = origVa & ~0xFFFFFull;  // page-align rough
        printf("\nClue: PML4 phys = 0x%llX, orig VA = 0x%llX, diff = 0x%llX\n",
               cr3 & 0x000FFFFFFFFFF000ull, origVa,
               (origVa > (cr3 & 0x000FFFFFFFFFF000ull))
                 ? origVa - (cr3 & 0x000FFFFFFFFFF000ull)
                 : (cr3 & 0x000FFFFFFFFFF000ull) - origVa);
    }
    return 0;
}

// hv_call_with_args: send command + 64-bit input args (RDX, R8) to the hook.
static int hv_call_with_args(UINT32 cmd, UINT64 a, UINT64 b, HOLY_CALL_IO* io) {
    HANDLE h = open_device();
    if (h == INVALID_HANDLE_VALUE) return -1;
    memset(io, 0, sizeof(*io));
    io->command = cmd;
    io->in_a    = a;       // -> RDX in hook
    io->in_b    = b;       // -> R8  in hook
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_HOLY_CALL,
                              io, sizeof(*io), io, sizeof(*io), &bytes, NULL);
    DWORD err = ok ? 0 : GetLastError();
    CloseHandle(h);
    if (!ok) { fprintf(stderr, "holyctl: hv IOCTL failed (err %lu)\n", err); return -1; }
    return 0;
}

static int cmd_probe_va(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "usage: holyctl probe-va <hex_host_va> [mode]\n");
        fprintf(stderr, "  mode 0 = echo-only (no deref, safe)  [default]\n");
        fprintf(stderr, "  mode 1 = read from &HookedVmExitHandlerIntel (ignore VA)\n");
        fprintf(stderr, "  mode 2 = read from user VA (original, risky)\n");
        fprintf(stderr, "  mode 3 = compare VA vs &HookedVmExitHandlerIntel (no deref)\n");
        return 1;
    }
    UINT64 va = (UINT64)_strtoui64(argv[0], NULL, 16);
    UINT64 mode = (argc >= 2) ? (UINT64)_strtoui64(argv[1], NULL, 0) : 0;
    if (mode >= 2 && va == 0) { fprintf(stderr, "VA cannot be 0 for mode 2\n"); return 1; }
    printf("probe-va: VA=0x%016llX mode=%llu\n", va, mode);
    HOLY_CALL_IO io;
    if (hv_call_with_args(HOLY_CMD_PROBE_VA, va, mode, &io)) return 1;
    printf("  status  = 0x%016llX\n", io.status);
    printf("  out_a   = 0x%016llX\n", io.out_a);
    printf("  out_b   = 0x%016llX\n", io.out_b);
    printf("  out_c   = 0x%016llX\n", io.out_c);
    if (mode == 0) {
        printf("  (echo test: out_a should == VA, out_b=0xEC000001, out_c=0xEC000002)\n");
    }
    return 0;
}

static int cmd_hookfn(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_HOOK_FN_VA, &io)) return 1;
    UINT64 hookVa   = io.out_a;   // hook runtime VA
    UINT64 hvBase   = io.out_b;   // hv runtime image base (correct)
    UINT64 origVa   = io.out_c;   // orig handler runtime VA
    printf("hook runtime VA    = 0x%016llX\n", hookVa);
    printf("hv image base      = 0x%016llX\n", hvBase);
    printf("orig handler VA    = 0x%016llX\n", origVa);
    printf("\nhook RVA in hv     = 0x%llX\n", hookVa - hvBase);
    printf("orig RVA in hv     = 0x%llX\n", origVa - hvBase);
    printf("hook-to-orig delta = 0x%llX\n", origVa - hookVa);
    return 0;
}

static int cmd_hv_read(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "usage: holyctl hv-read <hex_va> [count]\n");
        fprintf(stderr, "  reads qwords from hv host VA (default count=1, max 32)\n");
        return 1;
    }
    UINT64 va = (UINT64)_strtoui64(argv[0], NULL, 16);
    UINT32 count = (argc >= 2) ? (UINT32)strtoul(argv[1], NULL, 0) : 1;
    if (count == 0) count = 1;
    if (count > 32) count = 32;
    if (va == 0) { fprintf(stderr, "VA cannot be 0\n"); return 1; }

    for (UINT32 i = 0; i < count; i++) {
        UINT64 addr = va + i * 8;
        HOLY_CALL_IO io;
        if (hv_call_with_args(HOLY_CMD_HV_READ, addr, 0, &io)) return 1;
        if (io.status == HOLY_STATUS_BAD_VA) {
            fprintf(stderr, "hv-read: non-canonical VA 0x%016llX (top17=0x%llX)\n",
                    io.out_a, io.out_b);
            return 1;
        }
        if (io.status != HOLY_STATUS_OK) {
            fprintf(stderr, "hv-read at 0x%016llX failed (status 0x%X)\n",
                    addr, (UINT32)io.status);
            return 1;
        }
        printf("[0x%016llX] = 0x%016llX\n", addr, io.out_a);
    }
    return 0;
}

static int cmd_hv_write(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: holyctl hv-write <hex_va> <hex_value>\n");
        fprintf(stderr, "  writes one qword to hv host VA (RW pages only!)\n");
        return 1;
    }
    UINT64 va  = (UINT64)_strtoui64(argv[0], NULL, 16);
    UINT64 val = (UINT64)_strtoui64(argv[1], NULL, 16);
    if (va == 0) { fprintf(stderr, "VA cannot be 0\n"); return 1; }

    HOLY_CALL_IO io;
    if (hv_call_with_args(HOLY_CMD_HV_WRITE, va, val, &io)) return 1;
    if (io.status == HOLY_STATUS_BAD_VA) {
        fprintf(stderr, "hv-write: non-canonical VA 0x%016llX (top17=0x%llX)\n",
                io.out_a, io.out_b);
        return 1;
    }
    if (io.status != HOLY_STATUS_OK) {
        fprintf(stderr, "hv-write failed (status 0x%X) -- page not RW?\n",
                (UINT32)io.status);
        return 1;
    }
    printf("wrote 0x%016llX -> [0x%016llX]\n", val, va);
    printf("read-back: 0x%016llX  %s\n", io.out_a,
           (io.out_a == val) ? "OK" : "MISMATCH");
    return 0;
}

static int cmd_scratch_info(void) {
    // sub-mode 0: addresses
    HOLY_CALL_IO io;
    if (hv_call_with_args(HOLY_CMD_SCRATCH_INFO, 0, 0, &io)) return 1;
    UINT64 scratchVa  = io.out_a;
    UINT64 hvBase     = io.out_b;
    UINT64 scratchRva = io.out_c;
    printf("hv runtime base    = 0x%016llX\n", hvBase);
    printf("scratch RVA        = 0x%llX", scratchRva);
    if (scratchRva == 0) printf("  (DISABLED)");
    printf("\nscratch runtime VA = 0x%016llX", scratchVa);
    if (scratchVa == 0) printf("  (DISABLED)");
    printf("\n");

    // sub-mode 1: section diagnostics
    if (hv_call_with_args(HOLY_CMD_SCRATCH_INFO, 0, 1, &io)) return 1;
    UINT64 dataSecVa    = io.out_a;
    UINT64 dataSecVSize = io.out_b;
    UINT64 rawWinload   = io.out_c;
    printf("\n.data section RVA  = 0x%llX\n", dataSecVa);
    printf(".data VirtualSize  = 0x%llX  (after extension)\n", dataSecVSize);
    printf(".data mapped range = [hvBase+0x%llX .. hvBase+0x%llX)\n",
           dataSecVa, dataSecVa + dataSecVSize);
    printf("g_HolyScratch raw  = 0x%016llX  (winload VA)\n", rawWinload);

    if (scratchRva != 0 && dataSecVa != 0) {
        int inRange = (scratchRva >= dataSecVa &&
                       scratchRva + 0x1000 <= dataSecVa + dataSecVSize);
        printf("\nscratch RVA 0x%llX in .data range? %s\n",
               scratchRva, inRange ? "YES" : "NO <-- problem!");
    }

    if (scratchVa != 0) {
        printf("\ntest:  holyctl hv-read  %llX\n", scratchVa);
        printf("       holyctl hv-write %llX DEADBEEFCAFEBABE\n", scratchVa);
    }
    return 0;
}

static int cmd_host_dump(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_HOST_CR3, &io)) return 1;
    printf("HOST_CR3        = 0x%016llX  (PML4 phys = 0x%016llX)\n",
           io.out_a, io.out_a & 0x000FFFFFFFFFF000ull);
    printf("orig handler VA = 0x%016llX  (= hv image VA + 0x2118A0)\n", io.out_b);

    if (hv_call(HOLY_CMD_GET_HOST_RIP_GDT, &io)) return 1;
    printf("HOST_RIP        = 0x%016llX  (hv VMEXIT entry)\n", io.out_a);
    printf("HOST_GDTR_BASE  = 0x%016llX\n", io.out_b);
    printf("HOST_FS_BASE    = 0x%016llX\n", io.out_c);

    if (hv_call(HOLY_CMD_GET_HOST_RSP_IDT, &io)) return 1;
    printf("HOST_RSP        = 0x%016llX\n", io.out_a);
    printf("HOST_IDTR_BASE  = 0x%016llX\n", io.out_b);
    printf("HOST_TR_BASE    = 0x%016llX\n", io.out_c);
    return 0;
}

static int cmd_count(void) {
    HOLY_CALL_IO io;
    if (hv_call(HOLY_CMD_GET_VMEXIT_COUNT, &io)) return 1;
    printf("vmexit_count     = %llu\n", io.out_a);
    printf("last_exit_reason = %llu\n", io.out_b);
    printf("last_guest_rip   = 0x%016llX\n", io.out_c);
    return 0;
}


static int cmd_raw(int argc, char** argv) {
    if (argc < 1) { fprintf(stderr, "usage: holyctl raw <hex_cmd>\n"); return 1; }
    UINT32 cmd = (UINT32)strtoul(argv[0], NULL, 16);
    HOLY_CALL_IO io;
    if (hv_call(cmd, &io)) return 1;
    printf("cmd=%08X  status=%016llX  outA=%016llX outB=%016llX outC=%016llX\n",
           cmd, io.status, io.out_a, io.out_b, io.out_c);
    return 0;
}

static int cmd_read(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: holyctl read <pid> <hex_addr> <size>\n");
        return 1;
    }
    UINT32 pid  = (UINT32)strtoul(argv[0], NULL, 0);
    UINT64 addr = (UINT64)_strtoui64(argv[1], NULL, 16);
    UINT32 size = (UINT32)strtoul(argv[2], NULL, 0);
    UINT8  buf[HOLY_PROC_BUFSZ];
    if (size > HOLY_PROC_BUFSZ) size = HOLY_PROC_BUFSZ;
    if (proc_call(HOLY_PROC_READ, pid, addr, buf, size)) return 1;
    hex_dump(addr, buf, size);
    return 0;
}

static int cmd_write(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: holyctl write <pid> <hex_addr> <hex_bytes>\n");
        return 1;
    }
    UINT32 pid  = (UINT32)strtoul(argv[0], NULL, 0);
    UINT64 addr = (UINT64)_strtoui64(argv[1], NULL, 16);
    UINT8  buf[HOLY_PROC_BUFSZ];
    int n = hex_to_bytes(argv[2], buf, HOLY_PROC_BUFSZ);
    if (n <= 0) { fprintf(stderr, "holyctl: no valid hex bytes parsed\n"); return 1; }
    if (proc_call(HOLY_PROC_WRITE, pid, addr, buf, (UINT32)n)) return 1;
    printf("wrote %d byte(s) at pid=%u 0x%llX\n", n, pid, addr);
    return 0;
}

// List the loaded modules in <pid>. Use the printed base + size as the start
// and length for `holyctl read` / `scan`.
static int cmd_modules(int argc, char** argv) {
    if (argc < 1) { fprintf(stderr, "usage: holyctl modules <pid>\n"); return 1; }
    DWORD pid = (DWORD)strtoul(argv[0], NULL, 0);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "snapshot failed (err %lu) -- run as admin?\n", GetLastError());
        return 1;
    }
    MODULEENTRY32W me = { sizeof(me) };
    int n = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            wprintf(L"0x%016llX  size=0x%08X  %s\n",
                    (UINT64)(ULONG_PTR)me.modBaseAddr, me.modBaseSize, me.szModule);
            n++;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    if (n == 0) {
        fprintf(stderr, "no modules (pid wrong? or 32-bit/64-bit mismatch)\n");
        return 1;
    }
    return 0;
}

// List running processes (pid + name).
static int cmd_ps(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "snapshot failed (err %lu)\n", GetLastError());
        return 1;
    }
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            wprintf(L"%6u  %s\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

static int cmd_scan(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: holyctl scan <pid> <hex_addr> <size> <hex_bytes>\n");
        return 1;
    }
    UINT32 pid  = (UINT32)strtoul(argv[0], NULL, 0);
    UINT64 base = (UINT64)_strtoui64(argv[1], NULL, 16);
    UINT64 size = (UINT64)_strtoui64(argv[2], NULL, 0);
    UINT8  pat[256];
    int patN = hex_to_bytes(argv[3], pat, sizeof(pat));
    if (patN <= 0) { fprintf(stderr, "holyctl: bad pattern\n"); return 1; }

    UINT8 buf[HOLY_PROC_BUFSZ];
    UINT64 hits = 0;
    UINT64 offset = 0;
    while (offset < size) {
        UINT32 chunk = (UINT32)((size - offset > HOLY_PROC_BUFSZ)
                                ? HOLY_PROC_BUFSZ : (size - offset));
        if (proc_call(HOLY_PROC_READ, pid, base + offset, buf, chunk)) {
            // unreadable region; skip forward one page
            offset += 0x1000;
            continue;
        }
        for (UINT32 i = 0; i + (UINT32)patN <= chunk; i++) {
            if (memcmp(buf + i, pat, (size_t)patN) == 0) {
                printf("hit @ 0x%016llX\n", base + offset + i);
                hits++;
            }
        }
        offset += chunk;
    }
    printf("scan done -- %llu hit(s)\n", hits);
    return 0;
}

static void usage(void) {
    printf("hv hook commands:\n");
    printf("  holyctl ping\n");
    printf("  holyctl cr3\n");
    printf("  holyctl hookfn         -- hook VA + correct hv base + orig VA\n");
    printf("  holyctl scratch-info   -- scratch runtime VA + reloc delta\n");
    printf("  holyctl hv-read  <va> [count]   -- read qwords from hv memory\n");
    printf("  holyctl hv-write <va> <value>   -- write qword to hv memory (RW only)\n");
    printf("  holyctl probe-va <va> [mode]    -- low-level probe (mode 0/1/2/3)\n");
    printf("  holyctl host-dump      -- VMCS host fields\n");
    printf("  holyctl rva\n");
    printf("  holyctl scratch\n");
    printf("  holyctl count\n");
    printf("  holyctl raw <hex_cmd>\n");
    printf("process memory commands:\n");
    printf("  holyctl ps\n");
    printf("  holyctl modules <pid>\n");
    printf("  holyctl read    <pid> <hex_addr> <size>\n");
    printf("  holyctl write   <pid> <hex_addr> <hex_bytes>\n");
    printf("  holyctl scan    <pid> <hex_addr> <size> <hex_bytes>\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* sub = argv[1];
    if      (!strcmp(sub, "ping"))    return cmd_ping();
    else if (!strcmp(sub, "cr3"))     return cmd_cr3();
    else if (!strcmp(sub, "rva"))     return cmd_rva();
    else if (!strcmp(sub, "scratch")) return cmd_scratch();
    else if (!strcmp(sub, "count"))   return cmd_count();
    else if (!strcmp(sub, "host-cr3") || !strcmp(sub, "hostcr3"))
                                      return cmd_host_cr3();
    else if (!strcmp(sub, "host-dump") || !strcmp(sub, "hostdump"))
                                      return cmd_host_dump();
    else if (!strcmp(sub, "probe-va") || !strcmp(sub, "probeva"))
                                      return cmd_probe_va(argc - 2, argv + 2);
    else if (!strcmp(sub, "hookfn") || !strcmp(sub, "hook-fn"))
                                      return cmd_hookfn();
    else if (!strcmp(sub, "hv-read") || !strcmp(sub, "hvread"))
                                      return cmd_hv_read(argc - 2, argv + 2);
    else if (!strcmp(sub, "hv-write") || !strcmp(sub, "hvwrite"))
                                      return cmd_hv_write(argc - 2, argv + 2);
    else if (!strcmp(sub, "scratch-info") || !strcmp(sub, "scratchinfo"))
                                      return cmd_scratch_info();
    else if (!strcmp(sub, "raw"))     return cmd_raw(argc - 2, argv + 2);
    else if (!strcmp(sub, "read"))    return cmd_read(argc - 2, argv + 2);
    else if (!strcmp(sub, "write"))   return cmd_write(argc - 2, argv + 2);
    else if (!strcmp(sub, "patch"))   return cmd_write(argc - 2, argv + 2);
    else if (!strcmp(sub, "scan"))    return cmd_scan(argc - 2, argv + 2);
    else if (!strcmp(sub, "modules")) return cmd_modules(argc - 2, argv + 2);
    else if (!strcmp(sub, "ps"))      return cmd_ps();
    usage();
    return 1;
}
