# Cheat Driver Example

A kernel-mode driver written in C using the Kernel-Mode Driver Framework (KMDF) and a user-mode client. Demonstrates locating and modifying a game process’s in-memory value (player money for the game OpenTTD) from kernel space.

## Overview
Built with Visual Studio + WDK. Compiled to a `.sys` file and loaded with `sc` (create / start). A user-mode tool opens the driver device and sends the target process PID. The driver resolves the in-process money address via a module base plus a pointer-offset chain and writes a new integer value from kernel context.

## Key functions
- `DriverEntry`: initializes the driver, creates the device object and symbolic link, registers major functions, sets `DriverUnload`.
- Device object + symbolic link: enable user-mode handle via `CreateFile`.
- IRP handling: `IRP_MJ_DEVICE_CONTROL` handled by `IoControl`, which reads the PID from the I/O stack location and calls `AddMoney`.
- `PsLookupProcessByProcessId`: obtains `PEPROCESS`.
- `TracePointer`: computes dynamic address using `PsGetProcessSectionBaseAddress` as base and iterating a pointer chain with `KeReadProcessMemory`.
- Write performed via kernel memory-copy helpers (`MmCopyVirtualMemory` / wrapper) to set the money value.

## How it works
1. Load and start the driver with `sc`.  
2. User-mode client opens the symbolic link (`CreateFile`).  
3. Client calls `DeviceIoControl`, sending the PID.  
4. Driver resolves the PID, traces the pointer chain to the money address, writes the new value, completes the IRP.
