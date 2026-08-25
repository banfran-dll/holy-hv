#pragma once

#include "Global.h"

//
// Intel VM Exit Reasons
//
#define HOLY_VMX_EXIT_REASON_CPUID               10
#define HOLY_VMX_EXIT_REASON_VMCALL              18

//
// VMCS Fields used by the hook
//
// Intel SDM Vol.3 Appendix B (natural-width guest-state fields):
//   GUEST_CR3 = 0x6802, GUEST_RSP = 0x681C, GUEST_RIP = 0x681E.
// Pre-fix the CR3 macro collided with GUEST_RIP (both 0x681E), which would
// have silently mis-read RIP as CR3 in any future GetCommandIntel() / page-
// table-walk call. Not a magic-scan blocker, but a latent corruption bug.
#define HOLY_VMCS_GUEST_CR3                      0x00006802
#define HOLY_VMCS_GUEST_RSP                      0x0000681C
#define HOLY_VMCS_GUEST_RIP                      0x0000681E
#define HOLY_VMCS_EXIT_REASON                    0x00004402
#define HOLY_VMCS_VMEXIT_INSTRUCTION_LENGTH      0x0000440C

//
// Intel specific hook signature (Windows 11 hvix64.exe)
// Pattern: mov edx,rbp / call <mitigation> / mov rcx,[rsp+?] / sti /
//          mov edx,esi / or edx,[rsp+?] / call <handler> / jmp <loop_top>
// E8 at offset 19, displacement at offset 20 (scan+20 in HV.c).
//
#define INTEL_VMEXIT_HANDLER_SIG "8B D5 E8 ? ? ? ? 48 8B 4C 24 ? FB 8B D6 0B 54 24 ? E8 ? ? ? ? E9"

// Byte offsets within INTEL_VMEXIT_HANDLER_SIG (second E8 = CALL <handler>):
#define INTEL_SIG_HANDLER_CALL_OFF   19
#define INTEL_SIG_HANDLER_DISP_OFF   20
#define INTEL_SIG_HANDLER_END_OFF    24

extern UINT64 OriginalVmExitHandlerIntelAddr;

// Function prototypes
UINT64 HookedVmExitHandlerIntel(PGUEST_CONTEXT context, VOID* unknown);
