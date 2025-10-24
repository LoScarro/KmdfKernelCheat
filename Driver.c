#include <ntdef.h>
#include <ntifs.h>
#include <windef.h> // for DWORD

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

PDEVICE_OBJECT g_DeviceObject = NULL;
UNICODE_STRING DriverName, SymbolName;
PVOID ObHandle = NULL;

#pragma alloc_text(INIT, DriverEntry)

#define DEVICE_NAME L"\\Device\\KernelCheat"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\KernelCheatSL"
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// API function from ntoskrnl.exe used to copy memory to and from a user process
NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    PEPROCESS SourceProcess = Process;
    PEPROCESS TargetProcess = PsGetCurrentProcess();
    SIZE_T Result;

    NTSTATUS status = MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
    if (NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }
    else {
        return status;
    }
}

NTSTATUS KeWriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
    PEPROCESS SourceProcess = PsGetCurrentProcess();
    PEPROCESS TargetProcess = Process;
    SIZE_T Result;

    NTSTATUS status = MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
    if (NT_SUCCESS(status)) {
        return STATUS_SUCCESS;
    }
    else {
        return status;
    }
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMBOLIC_LINK_NAME);

    // Delete symbolic link
    IoDeleteSymbolicLink(&symLinkName);

    // Delete device object
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver unloaded\n");
}

// Structure to represent a memory pointer with offsets
struct memory_ptr {
    DWORD base_address;     // starting base address
    int total_offsets;      // offset depth
    int offsets[2];         // actual offsets
};

// Function to trace a pointer, starting from base and enumerate over each offset
uintptr_t* trace_pointer(PEPROCESS Process, struct memory_ptr* hack) {
    PVOID baseAddress = PsGetProcessSectionBaseAddress(Process);
    uintptr_t* location = (uintptr_t*)((uintptr_t)baseAddress + (uintptr_t)hack->base_address);

    for (int i = 0; i < hack->total_offsets; i++) {
        uintptr_t temp;
        KeReadProcessMemory(Process, location, &temp, sizeof(uintptr_t));
        location = (uintptr_t*)(temp + (int)hack->offsets[i]);
    }
    return location;
}

NTSTATUS AddMoney(ULONG targetProcessId)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "PID received, starting to write to process memory...\n");

    HANDLE targetPid = (HANDLE)targetProcessId;
    NTSTATUS status = STATUS_SUCCESS;
    int Writeval = 900000;
    PEPROCESS Process = NULL;

    status = PsLookupProcessByProcessId(targetPid, &Process);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to lookup process by ID: %x\n", status);
        return status;
    }

    struct memory_ptr money_hack_ptr = {
        0x00D5D380,
        2,
        { 0x0, 0x58 }
    };

    uintptr_t* money_address = trace_pointer(Process, &money_hack_ptr);

    status = KeWriteProcessMemory(Process, &Writeval, money_address, sizeof(int));
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to write to process memory: %x\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Successfully wrote to process memory. Value: %d\n", Writeval);
    return status;
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Open ok\n");
    return STATUS_SUCCESS;
}
NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Close ok\n");
    return STATUS_SUCCESS;
}

NTSTATUS DriverDispatchRoutine(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    PVOID buffer;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIo;
    pIo = IoGetCurrentIrpStackLocation(pIrp);
    pIrp->IoStatus.Information = 0;
    switch (pIo->MajorFunction)
    {
    case IRP_MJ_CREATE:
        NtStatus = STATUS_SUCCESS;
        break;
    case IRP_MJ_READ:
        NtStatus = STATUS_SUCCESS;
        break;
    case IRP_MJ_WRITE:
        break;
    case IRP_MJ_CLOSE:
        NtStatus = STATUS_SUCCESS;
        break;
    default:
        NtStatus = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return NtStatus;
}  

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status;
    ULONG BytesIO = 0;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    // Code received from user space
    ULONG userSignal = stack->Parameters.DeviceIoControl.IoControlCode;
	// Write to process memory
	status = AddMoney(userSignal);
	if (status != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to add money: %x\n", status);
	}

    // Complete the request
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pUniStr)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Driver %s", "loaded\n");
    
    NTSTATUS NtRet = STATUS_SUCCESS;
    PDEVICE_OBJECT pDeviceObj;
    
    RtlInitUnicodeString(&DriverName, DEVICE_NAME); // Giving the driver a name
    RtlInitUnicodeString(&SymbolName, SYMBOLIC_LINK_NAME); // Giving the driver a symbol
    
    NTSTATUS NtRet2 = IoCreateDevice(pDriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &pDeviceObj);
    
    if (NtRet2 == STATUS_SUCCESS)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateDevice ok\n");
        ULONG i;

        for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
        {
            pDriverObject->MajorFunction[i] = DriverDispatchRoutine;
        }

        NTSTATUS NtRet2 = IoCreateSymbolicLink(&SymbolName, &DriverName);
		if (NtRet2 != STATUS_SUCCESS)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink failed\n");
            return STATUS_UNSUCCESSFUL;
		}
        
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IoCreateSymbolicLink ok\n");
        
        pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
        pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
        pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

        pDeviceObj->Flags |= DO_DIRECT_IO;
        pDeviceObj->Flags &= (~DO_DEVICE_INITIALIZING);
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }

    pDriverObject->DriverUnload = DriverUnload; // Telling the driver, this is the unload function
     
    return STATUS_SUCCESS;
}
