// HolyHvProbe.sys
//
// Kernel-mode bridge between user-mode CLI (holyctl.exe) and the EFI-side
// VMEXIT hook. The driver receives an IOCTL with a command id (HOLY_CMD_*),
// issues a CPUID in kernel context (which Hyper-V always traps), and returns
// the four guest GPR slots the hook wrote into.

#include <ntifs.h>

#define HOLY_KEY 0xDEADC0DEu

#define IOCTL_HOLY_CALL    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HOLY_PROCMEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOLY_CALL_IO {
    UINT64 command;       // HOLY_CMD_* -> guest RAX
    UINT64 in_a;          // -> guest RDX
    UINT64 in_b;          // -> guest R8
    UINT64 status;        // <- guest RAX
    UINT64 out_a;         // <- guest RBX
    UINT64 out_b;         // <- guest RCX
    UINT64 out_c;         // <- guest RDX
} HOLY_CALL_IO, *PHOLY_CALL_IO;

#define HOLY_PROC_READ   0u
#define HOLY_PROC_WRITE  1u
#define HOLY_PROC_BUFSZ  0x1000u

#pragma pack(push, 1)
typedef struct _HOLY_PROCMEM_IO {
    UINT32 mode;                  // HOLY_PROC_READ or HOLY_PROC_WRITE
    UINT32 pid;                   // target process id
    UINT64 address;               // target virtual address
    UINT32 size;                  // bytes (<= HOLY_PROC_BUFSZ)
    UINT32 result;                // 0 == OK, else NTSTATUS
    UINT8  buffer[HOLY_PROC_BUFSZ];
} HOLY_PROCMEM_IO, *PHOLY_PROCMEM_IO;
#pragma pack(pop)

// HolyCpuid.asm: full 64-bit GPR round-trip across the CPUID trap.
extern void HolyDoCpuid(UINT64 rax_in, UINT64 rcx_in, UINT64* regs_out);
// 4 GP register inputs (rax, rcx, rdx, r8) -- lets us pass a 64-bit VA / size
// / pointer through to the hook.
extern void HolyDoCpuidEx(UINT64 rax_in, UINT64 rcx_in,
                          UINT64 rdx_in, UINT64 r8_in,
                          UINT64* regs_out);

static NTSTATUS HolyCreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Write into a user-mode address that may be read-only at the user level
// (e.g. .rsrc / .text of a loaded module). Standard trick:
//   1. IoAllocateMdl + MmProbeAndLockPages(KernelMode, IoReadAccess)
//      -- KernelMode + IoReadAccess locks even RO pages
//   2. MmGetSystemAddressForMdlSafe -- get a kernel VA alias to the same physical
//   3. MmProtectMdlSystemAddress(PAGE_READWRITE) -- mark the kernel alias RW
//   4. RtlCopyMemory through the kernel VA -- user PTE stays RO, write succeeds
// MDL must be created while attached to the target process so the user VA
// resolves to the right physical pages.
static NTSTATUS HolyForceWrite(PVOID dest, const VOID* src, ULONG size)
{
    PMDL mdl = IoAllocateMdl(dest, size, FALSE, FALSE, NULL);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS s = STATUS_SUCCESS;
    BOOLEAN locked = FALSE;
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        locked = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
    }

    if (NT_SUCCESS(s)) {
        PVOID kva = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if (!kva) {
            s = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            NTSTATUS ps = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            if (NT_SUCCESS(ps)) {
                __try {
                    RtlCopyMemory(kva, src, size);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    s = GetExceptionCode();
                }
            } else {
                s = ps;
            }
        }
    }

    if (locked) MmUnlockPages(mdl);
    IoFreeMdl(mdl);
    return s;
}

// Read/write user-mode memory of another process by attaching to its CR3.
// Read uses ProbeForRead + RtlCopyMemory (works for RO pages).
// Write uses the MDL re-protect trick above so RO pages (.text, .rsrc, ...)
// can be patched.
static NTSTATUS HolyProcMem(PHOLY_PROCMEM_IO io)
{
    if (io->size == 0 || io->size > HOLY_PROC_BUFSZ) return STATUS_INVALID_PARAMETER;
    if (io->mode != HOLY_PROC_READ && io->mode != HOLY_PROC_WRITE)
        return STATUS_INVALID_PARAMETER;

    PEPROCESS proc = NULL;
    NTSTATUS s = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)io->pid, &proc);
    if (!NT_SUCCESS(s)) { io->result = s; return STATUS_SUCCESS; }

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    if (io->mode == HOLY_PROC_READ) {
        s = STATUS_SUCCESS;
        __try {
            ProbeForRead((PVOID)io->address, io->size, 1);
            RtlCopyMemory(io->buffer, (PVOID)io->address, io->size);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s = GetExceptionCode();
        }
    } else {
        s = HolyForceWrite((PVOID)io->address, io->buffer, io->size);
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(proc);

    io->result = (UINT32)s;
    return STATUS_SUCCESS;   // IOCTL itself OK; per-op error in io->result
}

static NTSTATUS HolyIoctl(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    const ULONG code = sp->Parameters.DeviceIoControl.IoControlCode;

    if (code == IOCTL_HOLY_CALL &&
        sp->Parameters.DeviceIoControl.InputBufferLength  >= sizeof(HOLY_CALL_IO) &&
        sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HOLY_CALL_IO))
    {
        PHOLY_CALL_IO io = (PHOLY_CALL_IO)irp->AssociatedIrp.SystemBuffer;
        UINT64 regs[4] = { 0, 0, 0, 0 };
        // Wire-up: command -> RAX, KEY -> RCX, in_a -> RDX, in_b -> R8.
        HolyDoCpuidEx(io->command, (UINT64)HOLY_KEY,
                      io->in_a, io->in_b, regs);
        io->status = regs[0];
        io->out_a  = regs[1];
        io->out_b  = regs[2];
        io->out_c  = regs[3];
        info = sizeof(HOLY_CALL_IO);
        status = STATUS_SUCCESS;
    }
    else if (code == IOCTL_HOLY_PROCMEM &&
             sp->Parameters.DeviceIoControl.InputBufferLength  >= sizeof(HOLY_PROCMEM_IO) &&
             sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HOLY_PROCMEM_IO))
    {
        PHOLY_PROCMEM_IO io = (PHOLY_PROCMEM_IO)irp->AssociatedIrp.SystemBuffer;
        status = HolyProcMem(io);
        info   = sizeof(HOLY_PROCMEM_IO);
    }
    else {
        // Anything that fell through above stays as STATUS_INVALID_DEVICE_REQUEST.
        // Trace the code + buffer sizes so DebugView shows why.
        DbgPrint("HolyHvProbe: unmatched IOCTL code=0x%X in=%u out=%u "
                 "(expect_call=0x%X expect_procmem=0x%X sizeof(call)=%u sizeof(procmem)=%u)\n",
                 code,
                 sp->Parameters.DeviceIoControl.InputBufferLength,
                 sp->Parameters.DeviceIoControl.OutputBufferLength,
                 IOCTL_HOLY_CALL,
                 IOCTL_HOLY_PROCMEM,
                 (UINT32)sizeof(HOLY_CALL_IO),
                 (UINT32)sizeof(HOLY_PROCMEM_IO));
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static VOID HolyUnload(PDRIVER_OBJECT drv) {
    UNICODE_STRING sym = RTL_CONSTANT_STRING(L"\\DosDevices\\HolyHvProbe");
    IoDeleteSymbolicLink(&sym);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\HolyHvProbe");
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\DosDevices\\HolyHvProbe");
    PDEVICE_OBJECT dev = NULL;

    NTSTATUS s = IoCreateDevice(drv, 0, &devName,
                                FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(s)) return s;

    s = IoCreateSymbolicLink(&symName, &devName);
    if (!NT_SUCCESS(s)) { IoDeleteDevice(dev); return s; }

    drv->MajorFunction[IRP_MJ_CREATE]         = HolyCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]          = HolyCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HolyIoctl;
    drv->DriverUnload = HolyUnload;
    return STATUS_SUCCESS;
}
