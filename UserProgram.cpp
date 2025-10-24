#include <Windows.h>
#include <iostream>
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

// Return the PID of the target process
int findPID(std::wstring targetProcessName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // all processes

    PROCESSENTRY32W entry; // current process
    entry.dwSize = sizeof entry;

    if (!Process32FirstW(snap, &entry))
    {
        return 0;
    }

    do
    {
        if (std::wstring(entry.szExeFile) == targetProcessName)
        {
            return entry.th32ProcessID; // name matches; add to list
        }
    } while (Process32NextW(snap, &entry)); // keep going until end of snapshot
    return 0;
}

int main()
{
    HANDLE hDevice = CreateFileA("\\\\.\\KernelCheatSL", GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to open device. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    std::cout << "Device opened successfully!" << std::endl;

    // Get the game pid
    int targetProcessPID = findPID(L"openttd.exe");
    std::cout << "Target process PID: " << targetProcessPID << std::endl;
    
    if (targetProcessPID == 0)
    {
        std::cerr << "Failed to find the target process PID. Error code: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    // Send IOCTL command to the driver
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, targetProcessPID, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        std::cerr << "Failed to send IOCTL command. Error code: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    std::cout << "IOCTL command sent successfully!" << std::endl;

    // Close the handle
    CloseHandle(hDevice);

    return 0;
}
