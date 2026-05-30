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

static NTSTATUS HolyCreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Read/write user-mode memory of another process by attaching to its CR3.
// This is a normal kernel-driver power (anti-cheat / EDR can see it, and
// PatchGuard does not stop it). The hv-side path will be added in phase C.
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

    s = STATUS_SUCCESS;
    __try {
        if (io->mode == HOLY_PROC_READ) {
            ProbeForRead((PVOID)io->address, io->size, 1);
            RtlCopyMemory(io->buffer, (PVOID)io->address, io->size);
        } else {
            ProbeForWrite((PVOID)io->address, io->size, 1);
            RtlCopyMemory((PVOID)io->address, io->buffer, io->size);
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        s = GetExceptionCode();
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
        HolyDoCpuid(io->command, (UINT64)HOLY_KEY, regs);
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
