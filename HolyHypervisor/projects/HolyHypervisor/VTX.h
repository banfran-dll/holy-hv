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
// Intel VMEXIT handler signature table.
// Each entry matches a known Win11 hvix64.exe dispatch-loop pattern.
// Table-driven so new builds just add a row; first match wins.
//
//   call_off  = byte offset of the E8 (CALL handler) opcode within the match
//   disp_off  = byte offset of that CALL's rel32 displacement
//   end_off   = byte offset past the CALL instruction (= IP base for rel32)
//
typedef struct _INTEL_VMEXIT_SIG_ENTRY {
    const CHAR8* pattern;
    UINT16 call_off;
    UINT16 disp_off;
    UINT16 end_off;
    const CHAR8* build;
} INTEL_VMEXIT_SIG_ENTRY;

//
// GPR array indices for Intel's dispatcher context.
// hvix64 saves guest GPRs in x86 register-encoding order.
// *ctx (first qword of the dispatcher wrapper) points to this array.
//
#define INTEL_GPR_RAX    0
#define INTEL_GPR_RCX    1
#define INTEL_GPR_RDX    2
#define INTEL_GPR_RBX    3
#define INTEL_GPR_RSP    4
#define INTEL_GPR_RBP    5
#define INTEL_GPR_RSI    6
#define INTEL_GPR_RDI    7
#define INTEL_GPR_R8     8
#define INTEL_GPR_R9     9
#define INTEL_GPR_R10   10
#define INTEL_GPR_R11   11
#define INTEL_GPR_R12   12
#define INTEL_GPR_R13   13
#define INTEL_GPR_R14   14
#define INTEL_GPR_R15   15

extern UINT64 OriginalVmExitHandlerIntelAddr;

UINT64 HookedVmExitHandlerIntel(PGUEST_CONTEXT context, VOID* unknown);
