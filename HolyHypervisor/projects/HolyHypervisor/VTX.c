#include "Global.h"
#include "VTX.h"

BOOLEAN CalledVmExitIntel = FALSE;
BOOLEAN CalledVtlReturnIntel = FALSE;

UINT64 OriginalVmExitHandlerIntelAddr = 0;
extern SECUREKERNEL_INFO SecureKernelInfo;
extern ENCLAVE_INFO EnclaveInfo;

COMMAND_DATA GetCommandIntel(const PGUEST_CONTEXT context)
{
    UINT64 guestCr3;
    __vmx_vmread(HOLY_VMCS_GUEST_CR3, &guestCr3);

    // CR3 contains other bits (like PCIDE), mask to get PFN and shift
    CR3 cr3;
    cr3.AsUInt = guestCr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    return *(COMMAND_DATA*)commandPage;
}

VOID SetCommandIntel(const PGUEST_CONTEXT context, COMMAND_DATA* data)
{
    UINT64 guestCr3;
    __vmx_vmread(HOLY_VMCS_GUEST_CR3, &guestCr3);

    CR3 cr3;
    cr3.AsUInt = guestCr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    *(COMMAND_DATA*)commandPage = *data;
}

VOID HandleCPUIDIntel(const PGUEST_CONTEXT context)
{
    COMMAND_DATA data;
    UINT64 guestCr3;
    __vmx_vmread(HOLY_VMCS_GUEST_CR3, &guestCr3);

    switch (context->Rdx)
    {
    case COMMAND_CHECK_PRESENCE:
        context->Rax = CPUID_RETURN_VALUE;
        break;
    case COMMAND_INIT_MEMORY:
        context->Rax = MemoryInit();
        break;
    case COMMAND_GET_CR3:
        context->Rax = guestCr3;
        break;
    case COMMAND_VIRTUAL_MEMORY_COPY:
        data = GetCommandIntel(context);
        context->Rax = MemoryCopyGuestVirtual(data.VirtualMemoryCopy.SourceCr3, data.VirtualMemoryCopy.SourceAddress, data.VirtualMemoryCopy.DestinationCr3, data.VirtualMemoryCopy.DestinationAddress, data.VirtualMemoryCopy.Size);
        break;
    case COMMAND_READ_PHYSICAL:
        data = GetCommandIntel(context);
        context->Rax = MemoryReadPhysical(data.ReadPhysical.PhysicalSourceAddress, data.ReadPhysical.Cr3, data.ReadPhysical.VirtualDestinationAddress, data.ReadPhysical.Size);
        break;
    case COMMAND_SECUREKERNEL_INFO:
        data.SecureKernelData.BaseVirtual = SecureKernelInfo.BaseAddressVirtual;
        data.SecureKernelData.BasePhysical = SecureKernelInfo.BaseAddressPhysical;
        data.SecureKernelData.Size = SecureKernelInfo.Size;
        data.SecureKernelData.CR3 = SecureKernelInfo.CR3;
        SetCommandIntel(context, &data);
        break;
    case COMMAND_ENCLAVE_INFO:
        data.EnclaveData.TotalCalls = EnclaveInfo.TotalCalls;
        data.EnclaveData.LastRip = EnclaveInfo.LastRip;
        data.EnclaveData.LastCR3 = EnclaveInfo.LastCR3;
        SetCommandIntel(context, &data);
        break;
    default:
        break;
    }
}

VOID HandleVTL1ToVTL0Intel(PGUEST_CONTEXT context)
{
    UINT64 guestCr3, guestRsp;
    __vmx_vmread(HOLY_VMCS_GUEST_CR3, &guestCr3);
    __vmx_vmread(HOLY_VMCS_GUEST_RSP, &guestRsp);

    const UINT64 rspPhysical = MemoryTranslateGuestVirtual(guestCr3, guestRsp, MapSource);
    if (!rspPhysical) {
        DebugFormat("Failed to translate RSP\n");
        return;
    }
    const UINT64 rspMapped = MemoryMapPage(rspPhysical, MapSource);

    const UINT64 returnAddress = *(UINT64*)rspMapped;
    const UINT64 returnPhysical = MemoryTranslateGuestVirtual(guestCr3, returnAddress, MapSource);
    if (!returnPhysical) {
        DebugFormat("Failed to translate return address\n");
        return;
    }

    UINT64 guestRip;
    __vmx_vmread(HOLY_VMCS_GUEST_RIP, &guestRip);

    DebugFormat("VTL1 to VTL0 transition (Intel):\n");
    DebugFormat(" - RIP: 0x%p\n", guestRip);
    DebugFormat(" - RSP: 0x%p\n", guestRsp);
    DebugFormat(" - CR3: 0x%p\n", guestCr3);
    DebugFormat(" - Stack physical: 0x%p\n", rspPhysical);
    DebugFormat(" - Stack mapped: 0x%p\n", rspMapped);
    DebugFormat(" - Return virtual: 0x%p\n", returnAddress);
    DebugFormat(" - Return physical: 0x%p\n", returnPhysical);

    UINT64 currentPagePhysical = returnPhysical & ~0xFFF;
    const UINT64 searchLimit = 1024 * 1024 * 64; // 64mb
    UINT64 searchCount = 0;

    while (searchCount < searchLimit)
    {
        const UINT64 currentPageMapped = MemoryMapPage(currentPagePhysical, MapSource);
        const PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)currentPageMapped;
        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            if (dosHeader->e_lfanew > 0 && dosHeader->e_lfanew < 4096 - sizeof(IMAGE_NT_HEADERS))
            {
                const PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((UINT64)dosHeader + dosHeader->e_lfanew);
                if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
                {
                    DebugFormat("Found securekernel.exe:\n");
                    DebugFormat(" - Base virtual: 0x%p\n", ntHeaders->OptionalHeader.ImageBase);
                    DebugFormat(" - Base physical: 0x%p\n", currentPagePhysical);
                    DebugFormat(" - Checksum: 0x%x\n", ntHeaders->OptionalHeader.CheckSum);
                    DebugFormat(" - Size of image: 0x%x\n", ntHeaders->OptionalHeader.SizeOfImage);

                    SecureKernelInfo.BaseAddressVirtual = ntHeaders->OptionalHeader.ImageBase;
                    SecureKernelInfo.BaseAddressPhysical = currentPagePhysical;
                    SecureKernelInfo.Size = ntHeaders->OptionalHeader.SizeOfImage;
                    SecureKernelInfo.CR3 = guestCr3;
                    break;
                }
            }
        }

        currentPagePhysical -= 4096;
        searchCount += 4096;
    }

    if (searchCount >= searchLimit)
    {
        DebugFormat("No image was found\n");
        return;
    }
}

// v35: Voyager-confirmed VMEXIT layout.
//
// All earlier probes (v30..v34) failed to locate guest state because they made
// two wrong assumptions:
//
//   1. They treated the first arg as `pcontext_t` directly. In Voyager's
//      WINVER > 1803 path the signature is `vmexit_handler(pcontext_t* ctx, ...)`
//      -- POINTER TO POINTER. The real context lives at `*ctx`, not `ctx`.
//
//   2. They keyed off guest RAX as the magic leaf. Voyager's protocol uses
//      `guest_registers->rcx == VMEXIT_KEY` as the trigger; RAX is unused
//      for routing and RDX carries the sub-command.
//
// Voyager's context_t layout (Intel payload, types.h):
//
//      offset  field    used here
//      ------  -----    ---------
//      0x00    rax      response RAX (sentinel out)
//      0x08    rcx      magic key in
//      0x10    rdx      command in
//      0x18    rbx      response RBX
//      0x20    rsp
//      0x28    rbp
//      0x30    rsi
//      0x38    rdi
//      0x40    r8       data buffer ptr in (Voyager convention)
//      ...
//
// Matching user-mode probe (build & run on guest):
//
//      #include <intrin.h>
//      #include <stdio.h>
//      int main(void) {
//          int r[4] = {0};
//          __cpuidex(r, 0, 0xDEADC0DE);   // EAX=command(=0), ECX=KEY
//          printf("eax=%08X ebx=%08X ecx=%08X edx=%08X\n",
//                 r[0], r[1], r[2], r[3]);
//      }
//
// Expected on hit: eax=DEADBEEF ebx=C0FFEE01 ecx=CAFEBABE edx=FEEDFACE.
#define HOLY_VMEXIT_KEY 0xDEADC0DEull

UINT64 HookedVmExitHandlerIntel(PGUEST_CONTEXT context, VOID* unknown)
{
    (VOID)unknown;

    UINT64 exitReason = 0;
    __vmx_vmread(HOLY_VMCS_EXIT_REASON, &exitReason);
    if ((exitReason & 0xFFFFu) != 10) {
        return 0;   // not CPUID -> pass through
    }

    // v37 ECHO diagnostic.
    //
    // The hv disasm (thanks user) confirmed the layout:
    //
    //   context = DISPATCHER_CTX*  (rcx at sub_2118A0 entry)
    //   gprs    = *(GUEST_GPR_SAVE**)context  (first qword of DISPATCHER_CTX)
    //   gprs->rax = gprs[0], gprs->rcx = gprs[1],
    //   gprs->rdx = gprs[2], gprs->rbx = gprs[3], ...
    //
    // dispatcher 0x23E000 unconditionally calls sub_2118A0 for every VMEXIT
    // (no fast-path skip for CPUID), and gprs[1] is set to guest RCX at
    // 0x23E35C and never touched again before our hook.
    //
    // But v35 (which checks gprs[1] == KEY) didn't fire on the user-mode test.
    // Two remaining possibilities to distinguish:
    //
    //   A. The user-mode test's MSVC __cpuidex(buf, 0, 0xDEADC0DE) did NOT
    //      put 0xDEADC0DE into ECX as we assumed (compiler/wrapper interfered).
    //   B. Our deref / hook entry is fundamentally wrong despite matching the
    //      disasm.
    //
    // This v37 drops the KEY check entirely. For every user-mode CPUID exit
    // we echo the actual guest input registers back as sentinels:
    //
    //     gprs[0] (out RAX) <- 0xAA000000 | (guest_RAX & 0xFFFF)
    //     gprs[1] (out RCX) <- 0xBB000000 | (guest_RCX & 0xFFFF)
    //     gprs[2] (out RDX) <- 0xCC000000 | (guest_RDX & 0xFFFF)
    //     gprs[3] (out RBX) <- 0xDD000000 | (guest_RBX & 0xFFFF)
    //
    // Then skip orig + advance RIP. User-mode kernel CPUIDs (e.g. early init)
    // are unaffected because the RIP filter excludes kernel mode. User-space
    // CPUIDs will see this echo on every call -- most programs tolerate weird
    // CPUID output (graceful feature-detection fallback).
    //
    // Decoding (per user-mode dword R):
    //   (R >> 24) == 0xAA  -> hook reached gprs[0]; low 16 bits = guest RAX
    //   (R >> 24) == 0xBB  -> hook reached gprs[1]; low 16 bits = guest RCX
    //   (R >> 24) == 0xCC  -> hook reached gprs[2]; low 16 bits = guest RDX
    //   (R >> 24) == 0xDD  -> hook reached gprs[3]; low 16 bits = guest RBX
    //
    // If user-mode test (__cpuidex(r,0,0xDEADC0DE)) gets back:
    //   r[0]=0xAA0000xx, r[1]=0xDD0000xx, r[2]=0xBB00C0DE, r[3]=0xCC0000xx
    // then everything works, layout is correct, and the v35 magic check
    // would have hit -- the v35 failure was just compiler quirks in the test.
    //
    // If r[2] != 0xBB00C0DE: hv saw a different ECX than we expected.
    //   The lower 16 bits of r[2] tell us what ECX actually was at CPUID time.
    // If r[*] != 0xAA/BB/CC/DD: hook didn't fire OR deref/offset wrong.
    // v38: kernel-mode CPUID with explicit ECX key.
    //
    // v37 (user-mode-only echo) silently passed through every user CPUID.
    // The combination of (a) v29 having hung when ALL CPUIDs were intercepted,
    // (b) Voyager/Tulach articles confirming user CPUID is unconditionally
    // trapped, and (c) the disasm confirming sub_2118A0 is always called,
    // means user-mode CPUID DOES reach our hook but our deref+offset assumption
    // doesn't survive on that path -- either the dispatcher ctx layout is
    // different for user-mode exits, or canonical check on gprs is rejecting
    // a non-kernel pointer that we should still trust.
    //
    // v38 sidesteps the question. Hook is now triggered from a kernel-mode
    // driver (HolyHvProbe) which calls __cpuidex(0, 0xDEADC0DE). Kernel CPUID
    // always traps. Filter:
    //
    //     kernel-mode RIP   AND   (UINT32)gprs[1] == 0xDEADC0DE
    //
    // The ECX==KEY check protects all other kernel CPUIDs (boot stays safe).
    // If hook fires and the driver-issued CPUID returns 0xDEADBEEF etc, we
    // confirm everything works for kernel CPUID; user-mode failure was a
    // separate VMCS / dispatch path issue we can chase later.
    // v41: protocol stage 1 -- PING command.
    //
    // v40 result locked the layout: gprs = *(UINT64**)context, and the GPR
    // save area uses the standard Voyager / user-disasm offsets
    //   gprs[0] = RAX, gprs[1] = RCX, gprs[2] = RDX, gprs[3] = RBX, ...
    //
    // The strict `> 0xFFFF800000000000` canonical check was the silent killer
    // in v35/v38 -- this hv stores the GPR save area in low-canonical mapped
    // memory, so we accept any plausibly non-NULL pointer (> 0x1000).
    //
    // Protocol (user-mode and kernel-mode both work):
    //   CPUID with  RCX == HOLY_HV_MAGIC_KEY     -> hook intercepts
    //               RAX == command code
    //   On return:  RAX/RBX/RCX/RDX hold command-specific response
    //
    // Commands implemented in v41:
    //   COMMAND_PING (0x10000001) -> RAX=0xDEADBEEF RBX=0xC0FFEE01
    //                                RCX=0xCAFEBABE RDX=0xFEEDFACE
    //
    // Magic key is a 32-bit unique value carried in guest ECX; false-positive
    // collision with a real kernel CPUID's ECX is astronomically unlikely.
    UINT64 rip = 0, len = 0;
    __vmx_vmread(HOLY_VMCS_GUEST_RIP, &rip);

    if ((UINT64)context <= 0x1000ull) return 0;
    UINT64* gprs = *(UINT64**)context;
    if ((UINT64)gprs <= 0x1000ull) return 0;

    if ((UINT32)gprs[1] != (UINT32)HOLY_VMEXIT_KEY) return 0;

    switch ((UINT32)gprs[0]) {
        case 0x10000001u:   // COMMAND_PING
            gprs[0] = 0xDEADBEEFull;   // -> guest RAX
            gprs[3] = 0xC0FFEE01ull;   // -> guest RBX
            gprs[1] = 0xCAFEBABEull;   // -> guest RCX
            gprs[2] = 0xFEEDFACEull;   // -> guest RDX
            break;
        default:
            // Unknown command: clear the response regs so the caller can tell.
            gprs[0] = 0;
            gprs[1] = 0;
            gprs[2] = 0;
            gprs[3] = 0;
            break;
    }

    __vmx_vmread(HOLY_VMCS_VMEXIT_INSTRUCTION_LENGTH, &len);
    __vmx_vmwrite(HOLY_VMCS_GUEST_RIP, rip + len);
    return 1;
}
