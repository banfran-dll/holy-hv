#include "Global.h"
#include "BuildMode.h"
#include "HolyProtocol.h"

#pragma warning(disable : 4146)

#define P2ALIGNUP(x, align) (-(-(x) & -(align)))

// (winload-stage PT walk removed for now -- triple-faulted because winload's
//  PT mapping is not phys=virt at BlLdrLoadImage time. The hook will translate
//  addresses through hv's own PT in a later step.)

extern IMAGE_DOS_HEADER __ImageBase;
VOID ProcessHvImage(const UINT64 imageBase, const CHAR16* imageName)
{
    static UINT64 diagnosedImages[4] = { 0 };
    BOOLEAN alreadyDiagnosed = FALSE;
    for (UINTN i = 0; i < 4; i++)
    {
        if (diagnosedImages[i] == imageBase)
        {
            alreadyDiagnosed = TRUE;
            break;
        }
    }

    if (alreadyDiagnosed)
    {
        DebugFormat("[HOLY-DIAG] HV image 0x%p already diagnosed; skipping duplicate ProcessHvImage.\n", (VOID*)imageBase);
        return;
    }

    for (UINTN i = 0; i < 4; i++)
    {
        if (diagnosedImages[i] == 0)
        {
            diagnosedImages[i] = imageBase;
            break;
        }
    }

    UINT64 scan = 0;
    BOOLEAN isIntel = FALSE;

    // Scan for Intel signature first
    scan = FindPatternImage((VOID*)imageBase, INTEL_VMEXIT_HANDLER_SIG);
    if (scan) {
        isIntel = TRUE;
    } else {
        // If Intel not found, try AMD signature
        scan = FindPatternImage((VOID*)imageBase, "E8 ? ? ? ? 48 89 04 24 E9");
    }

    if (!scan)
    {
        DebugFormat("[HOLY ERROR] VMEXIT handler signature not found in %s! Aborting injection.\n", imageName);
        return;
    }

    extern UINTN PatchedHyperV;
    PatchedHyperV = TRUE;

    const UINT64 currentImageBase = (UINT64)&__ImageBase;
    const UINT64 targetFunction = isIntel ? (UINT64)HookedVmExitHandlerIntel : (UINT64)HookedVmExitHandler;
    const UINT64 offset = targetFunction - currentImageBase;
    UINT32 payloadPeSize = 0;

    PIMAGE_DOS_HEADER payloadDosHeader = (PIMAGE_DOS_HEADER)&__ImageBase;
    if (payloadDosHeader->e_magic == IMAGE_DOS_SIGNATURE && payloadDosHeader->e_lfanew > 0 && payloadDosHeader->e_lfanew < 0x1000)
    {
        PIMAGE_NT_HEADERS64 payloadNtHeaders = (PIMAGE_NT_HEADERS64)((UINT64)&__ImageBase + payloadDosHeader->e_lfanew);
        if (payloadNtHeaders->Signature == IMAGE_NT_SIGNATURE)
        {
            payloadPeSize = payloadNtHeaders->OptionalHeader.SizeOfImage;
        }
    }

    DebugFormat("[HOLY] hv=%p scan=%p target=%p payload=0x%X\n",
        (VOID*)imageBase, (VOID*)scan, (VOID*)targetFunction, payloadPeSize);

    extern BOOLEAN ExtendedSize;
    if (!ExtendedSize) {
        DebugFormat("[HOLY] abort: hv buffer was not extended\n");
        return;
    }

#if HOLY_HV_MUTATION_STAGE == HOLY_HV_MUTATION_STAGE_NONE
    DebugFormat("[HOLY] %a: STAGE_NONE (mutation disabled)\n", HOLY_BUILD_MARKER);
    return;
#else
    DebugFormat("[HOLY] %a: stage=%d\n", HOLY_BUILD_MARKER, HOLY_HV_MUTATION_STAGE);
    if (payloadPeSize == 0) {
        DebugFormat("[HOLY] abort: payloadPeSize == 0\n");
        return;
    }

    // Sanity: scan+19 must be a near CALL (0xE8), and the target must lie
    // inside hv.exe's original image range.
    if (isIntel)
    {
        if (*(UINT8*)(scan + 19) != 0xE8) {
            DebugFormat("[HOLY] abort: scan+19 is not 0xE8\n");
            return;
        }
        UINT64 origTarget = scan + 24 + *(INT32*)(scan + 20);
        if (origTarget < imageBase || origTarget >= imageBase + 0x1600000) {
            DebugFormat("[HOLY] abort: origTarget 0x%p outside hv image\n", (VOID*)origTarget);
            return;
        }
    }

    // Place the payload in the executable padding at the end of hv.exe's first
    // executable section. PE headers are not modified -- hv still sees its
    // original layout, but the payload now sits within hv's self-mapped range.
    PIMAGE_DOS_HEADER hvDos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS64 hvNt = (PIMAGE_NT_HEADERS64)(imageBase + hvDos->e_lfanew);
    PIMAGE_SECTION_HEADER hvSecs = IMAGE_FIRST_SECTION(hvNt);
    PIMAGE_SECTION_HEADER textSec = NULL;
    UINT16 textIdx = 0;
    for (UINT16 si = 0; si < hvNt->FileHeader.NumberOfSections; si++) {
        if (hvSecs[si].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) {
            textSec = &hvSecs[si];
            textIdx = si;
            break;
        }
    }
    if (!textSec) {
        DebugFormat("[HOLY] abort: no executable section in hv\n");
        return;
    }

    UINT32 textEndRva = textSec->VirtualAddress + textSec->Misc.VirtualSize;
    UINT32 hookRva = P2ALIGNUP(textEndRva, EFI_PAGE_SIZE);
    UINT32 nextSecRva = (textIdx + 1 < hvNt->FileHeader.NumberOfSections)
                       ? hvSecs[textIdx + 1].VirtualAddress
                       : hvNt->OptionalHeader.SizeOfImage;
    UINT32 padSize = (nextSecRva > hookRva) ? (nextSecRva - hookRva) : 0;
    if (padSize < payloadPeSize) {
        DebugFormat("[HOLY] abort: .text padding 0x%X < payload 0x%X\n", padSize, payloadPeSize);
        return;
    }

    // hv self-maps each section based on VirtualAddress + VirtualSize. Pages
    // in the inter-section gap (past VirtualSize) are NOT in hv's own page
    // table. Extend .text VirtualSize so every page we touch is mapped RX.
    UINT32 requiredVSize = (hookRva + payloadPeSize) - textSec->VirtualAddress;
    if (requiredVSize > textSec->Misc.VirtualSize) {
        textSec->Misc.VirtualSize = requiredVSize;
    }

    const UINT64 section = imageBase + hookRva;
    const UINT64 remoteFunction = section + offset;
    DebugFormat("[HOLY] .text padding: hookRva=0x%X section=%p remoteFn=%p\n",
        hookRva, (VOID*)section, (VOID*)remoteFunction);

    const UINT64 originalBase = scan + 5;
    const INT32 originalOffset = *(INT32*)(scan + 1);
    const UINT64 originalFunction = originalBase + originalOffset;
    const INT32 newOffset = (INT32)(remoteFunction - originalBase);
    (VOID)originalFunction;
    (VOID)newOffset;

    // These must be set before CopyMem so the copied payload carries them.
    extern UINT64 g_HookRva;
    extern UINT64 g_HvWinloadBase;
    extern UINT64 g_ScratchRva;
    extern UINT64 g_DataSecVa;
    extern UINT64 g_DataSecVSize;
    g_HookRva = hookRva;
    g_HvWinloadBase = imageBase;

#if HOLY_HV_MUTATION_STAGE >= HOLY_HV_MUTATION_STAGE_PATCH
    if (isIntel) {
        OriginalVmExitHandlerIntelAddr = scan + 24 + *(INT32*)(scan + 20);
    }
#endif

    // Find one RW page inside hv's .data padding for our scratch struct.
    // Same trick as the .text padding: extend the section's VirtualSize so
    // the page falls inside hv's own self-map and is mapped RW.
    extern UINT64 g_HolyScratch;
    {
        PIMAGE_SECTION_HEADER dataSec = NULL;
        UINT16 dataIdx = 0;
        for (UINT16 si = 0; si < hvNt->FileHeader.NumberOfSections; si++) {
            UINT32 ch = hvSecs[si].Characteristics;
            if ((ch & EFI_IMAGE_SCN_MEM_WRITE) && !(ch & EFI_IMAGE_SCN_MEM_EXECUTE)) {
                dataSec = &hvSecs[si];
                dataIdx = si;
                break;
            }
        }
        if (dataSec) {
            g_DataSecVa = dataSec->VirtualAddress;
            UINT32 dEndRva     = dataSec->VirtualAddress + dataSec->Misc.VirtualSize;
            UINT32 scratchRva  = P2ALIGNUP(dEndRva, EFI_PAGE_SIZE);
            UINT32 nextSecRva2 = (dataIdx + 1 < hvNt->FileHeader.NumberOfSections)
                                 ? hvSecs[dataIdx + 1].VirtualAddress
                                 : hvNt->OptionalHeader.SizeOfImage;
            UINT32 dataPadSize = (nextSecRva2 > scratchRva) ? (nextSecRva2 - scratchRva) : 0;
            if (dataPadSize >= EFI_PAGE_SIZE) {
                UINT32 required = (scratchRva + EFI_PAGE_SIZE) - dataSec->VirtualAddress;
                if (required > dataSec->Misc.VirtualSize) {
                    dataSec->Misc.VirtualSize = required;
                }
                g_ScratchRva = scratchRva;
                g_DataSecVSize = dataSec->Misc.VirtualSize;
                g_HolyScratch = imageBase + scratchRva;
                DebugFormat("[HOLY] scratch=0x%p rva=0x%X (.data padding)\n",
                    (VOID*)g_HolyScratch, scratchRva);
            } else {
                g_DataSecVSize = dataSec->Misc.VirtualSize;
                DebugFormat("[HOLY] .data padding too small (0x%X) -- scratch disabled\n",
                    dataPadSize);
            }
        } else {
            DebugFormat("[HOLY] no RW section found -- scratch disabled\n");
        }
    }

    // Copy our PE image into the hv .text padding.
    CopyMem((VOID*)section, (VOID*)&__ImageBase, payloadPeSize);

#if HOLY_HV_MUTATION_STAGE < HOLY_HV_MUTATION_STAGE_RELOC
    DebugFormat("[HOLY] STAGE_COPYMEM complete (hook not armed)\n");
    return;
#else
    // Apply base relocations to the copy.
    const UINT64 delta = section - (UINT64)&__ImageBase;
    PIMAGE_NT_HEADERS64 payloadNtHeaders =
        (PIMAGE_NT_HEADERS64)((UINT64)&__ImageBase + payloadDosHeader->e_lfanew);

    UINT32 relocRva  = payloadNtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    UINT32 relocSize = payloadNtHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRva && relocSize) {
        EFI_IMAGE_BASE_RELOCATION* relocDir = (EFI_IMAGE_BASE_RELOCATION*)(section + relocRva);
        UINT32 processed = 0;
        while (processed < relocSize && relocDir->VirtualAddress) {
            if (relocDir->SizeOfBlock >= sizeof(EFI_IMAGE_BASE_RELOCATION)) {
                UINTN  count = (relocDir->SizeOfBlock - sizeof(EFI_IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
                UINT16* list = (UINT16*)(relocDir + 1);
                for (UINTN i = 0; i < count; i++) {
                    if ((list[i] >> 12) == EFI_IMAGE_REL_BASED_DIR64) {
                        UINT64* ptr = (UINT64*)(section + relocDir->VirtualAddress + (list[i] & 0xFFF));
                        *ptr += delta;
                    }
                }
            }
            processed += relocDir->SizeOfBlock;
            relocDir = (EFI_IMAGE_BASE_RELOCATION*)((UINT8*)relocDir + relocDir->SizeOfBlock);
        }
    }

#if HOLY_HV_MUTATION_STAGE < HOLY_HV_MUTATION_STAGE_PATCH
    DebugFormat("[HOLY] STAGE_RELOC complete (hook not armed)\n");
    return;
#else
    // Patch the VMEXIT CALL site to our 28-byte stub.
    if (isIntel)
    {
        // 28-byte stub at `section`. All branches are direct E8/E9/Jcc rel32/rel8
        // (CET-IBT exempt). The hook is a pre-handler that returns 0 to pass
        // through (stub JMPs to orig) or non-zero to skip orig (stub RETs back
        // to hv; hook is responsible for advancing guest RIP via VMCS).
        //
        //   [0]  51              push rcx
        //   [1]  52              push rdx
        //   [2]  48 83 EC 28     sub  rsp, 28h     ; MS x64 shadow space
        //   [6]  E8 <rel32>      call hook
        //   [11] 48 83 C4 28     add  rsp, 28h
        //   [15] 5A              pop  rdx
        //   [16] 59              pop  rcx
        //   [17] 48 85 C0        test rax, rax
        //   [20] 75 05           jnz  +5
        //   [22] E9 <rel32>      jmp  orig
        //   [27] C3              ret               ; back to scan+24
        {
            UINT8* stub = (UINT8*)section;
            const UINT64 origAddr = (UINT64)(scan + 24 + *(INT32*)(scan + 20));
            const UINT64 remoteFn = section + offset;

            stub[ 0] = 0x51;
            stub[ 1] = 0x52;
            stub[ 2] = 0x48; stub[ 3] = 0x83; stub[ 4] = 0xEC; stub[ 5] = 0x28;
            stub[ 6] = 0xE8;
            *(INT32*)(stub +  7) = (INT32)((INT64)remoteFn - (INT64)(section + 11));
            stub[11] = 0x48; stub[12] = 0x83; stub[13] = 0xC4; stub[14] = 0x28;
            stub[15] = 0x5A;
            stub[16] = 0x59;
            stub[17] = 0x48; stub[18] = 0x85; stub[19] = 0xC0;
            stub[20] = 0x75; stub[21] = 0x05;
            stub[22] = 0xE9;
            *(INT32*)(stub + 23) = (INT32)((INT64)origAddr - (INT64)(section + 27));
            stub[27] = 0xC3;

            *(INT32*)(scan + 20) = (INT32)((INT64)section - (INT64)(scan + 20) - 4);

            DebugFormat("[HOLY] stub@%p hook=%p orig=%p\n",
                (VOID*)section, (VOID*)remoteFn, (VOID*)origAddr);
        }
    }
    else
    {
        OriginalOffsetFromHook = (INT32)(originalFunction - remoteFunction);
        *(INT32*)(scan + 1) = newOffset;
    }
    DebugFormat("[HOLY] hook armed (orig=%p)\n",
        isIntel ? (VOID*)OriginalVmExitHandlerIntelAddr : (VOID*)(UINTN)OriginalOffsetFromHook);
#endif // PATCH

#endif // RELOC

#endif // STAGE_NONE vs mutation
}
