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

#define HOLY_STATUS_OK              0x00000000u

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
    printf("  holyctl patch   <pid> <hex_addr> <hex_bytes>     (alias for write)\n");
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    const char* sub = argv[1];
    if      (!strcmp(sub, "ping"))    return cmd_ping();
    else if (!strcmp(sub, "cr3"))     return cmd_cr3();
    else if (!strcmp(sub, "rva"))     return cmd_rva();
    else if (!strcmp(sub, "scratch")) return cmd_scratch();
    else if (!strcmp(sub, "count"))   return cmd_count();
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
