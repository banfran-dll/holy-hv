#include <windows.h>
#include <stdio.h>

#define IOCTL_HOLY_CPUID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct {
    UINT32 leaf, subleaf;
    UINT32 eax_out, ebx_out, ecx_out, edx_out;
} HOLY_CPUID_IO;

int main(void) {
    HANDLE h = CreateFileA("\\\\.\\HolyHvProbe",
                           GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\n", GetLastError());
        return 1;
    }

    HOLY_CPUID_IO io = {0};
    // v41+ protocol: RCX = magic key, RAX = command code.
    //   COMMAND_PING = 0x10000001 -> RAX=DEADBEEF RBX=C0FFEE01 RCX=CAFEBABE RDX=FEEDFACE
    io.leaf    = 0x10000001;   // EAX = COMMAND_PING
    io.subleaf = 0xDEADC0DE;   // ECX = magic key

    DWORD bytes = 0;
    if (!DeviceIoControl(h, IOCTL_HOLY_CPUID, &io, sizeof(io),
                         &io, sizeof(io), &bytes, NULL)) {
        printf("Ioctl failed: %lu\n", GetLastError());
        CloseHandle(h);
        return 1;
    }

    printf("eax=%08X ebx=%08X ecx=%08X edx=%08X\n",
           io.eax_out, io.ebx_out, io.ecx_out, io.edx_out);

    CloseHandle(h);
    return 0;
}
