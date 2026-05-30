#pragma once

//
// Shared protocol between the hv hook (EFI side), the kernel driver
// (HolyHvProbe.sys), and the user-mode CLI (holyctl.exe).
//
// Wire format on every command:
//
//   CPUID input:
//     RCX  = HOLY_KEY                   (magic, identifies our backdoor)
//     RAX  = HOLY_CMD_* (command id)
//     RDX  = command-specific input A
//     R8   = command-specific input B  (typically a pointer)
//
//   CPUID output (in the same GPR slots, overwritten by the hook):
//     RAX  = HOLY_STATUS_*              (0 == OK, non-zero == error)
//     RBX  = command-specific output A
//     RCX  = command-specific output B
//     RDX  = command-specific output C
//
// Both kernel and user mode CPUIDs reach the hook; the kernel driver is
// only used because some VBS configurations transparently virtualize
// user-mode CPUID and we cannot tell from inside whether the trap fired.
//

#define HOLY_KEY                0xDEADC0DEu

//
// Command ids.
// Upper 16 bits are a fixed magic to avoid collision with any leaf hv
// might emulate naturally; lower 16 bits identify the command.
//
#define HOLY_CMD_PING               0x10000001u
#define HOLY_CMD_GET_CR3            0x10000002u
#define HOLY_CMD_GET_VMEXIT_COUNT   0x10000003u
#define HOLY_CMD_GET_HOOK_RVA       0x10000004u
#define HOLY_CMD_GET_SCRATCH        0x10000005u  // returns scratch page base + size

//
// Layout of our RW scratch page (first page of hv .data padding).
// Hook reads its address from a payload-side global (g_HolyScratch), which
// the EFI side fills in pre-CopyMem.
//
typedef struct _HOLY_SCRATCH {
    UINT64 magic;               // = 'HOLYHOLY'  set by hook on first hit
    UINT64 vmexit_count;        // bumped every VMEXIT we intercept
    UINT64 last_exit_reason;
    UINT64 last_guest_rip;
    // remaining bytes available for command staging
    UINT8  reserved[0x1000 - 32];
} HOLY_SCRATCH;
#define HOLY_SCRATCH_MAGIC  0x594C4F48594C4F48ull   /* "HOLYHOLY" */

//
// Status codes returned in guest RAX.
//
#define HOLY_STATUS_OK              0x00000000u
#define HOLY_STATUS_UNKNOWN_CMD     0xE0000001u
#define HOLY_STATUS_BAD_ARG         0xE0000002u
