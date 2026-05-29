#include <ntddk.h>
#include <intrin.h>

#define IOCTL_HOLY_CPUID \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _HOLY_CPUID_IO {
    UINT32 leaf;
    UINT32 subleaf;
    UINT32 eax_out;
    UINT32 ebx_out;
    UINT32 ecx_out;
    UINT32 edx_out;
} HOLY_CPUID_IO, *PHOLY_CPUID_IO;

static NTSTATUS HolyCreateClose(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS HolyIoctl(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_HOLY_CPUID &&
        sp->Parameters.DeviceIoControl.InputBufferLength  >= sizeof(HOLY_CPUID_IO) &&
        sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(HOLY_CPUID_IO))
    {
        PHOLY_CPUID_IO io = (PHOLY_CPUID_IO)irp->AssociatedIrp.SystemBuffer;
        int regs[4] = {0};
        __cpuidex(regs, (int)io->leaf, (int)io->subleaf);
        io->eax_out = (UINT32)regs[0];
        io->ebx_out = (UINT32)regs[1];
        io->ecx_out = (UINT32)regs[2];
        io->edx_out = (UINT32)regs[3];
        info = sizeof(HOLY_CPUID_IO);
        status = STATUS_SUCCESS;
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
