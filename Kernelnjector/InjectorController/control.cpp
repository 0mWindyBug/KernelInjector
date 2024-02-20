#include <main.h>


bool SendInjectionRequest(PINJECTION_INFO InjectionInfo)
{
    DWORD BytesRet;
    HANDLE device = CreateFile(TARGET_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    AutoHandle AutHan(device);
    if (device == INVALID_HANDLE_VALUE) {
        std::cout << "[*] Failed to obtain  device handle" << std::endl;
        return -1;
    }
    
    BOOL success = DeviceIoControl(device, IOCTL_DLL_INJECT, InjectionInfo, sizeof(INJECTION_INFO), nullptr, 0, &BytesRet, nullptr);

    if (!success) {
        std::cout << "[*] Failed in DeviceIoControl: " << GetLastError() << std::endl;
        return -1;
    }
    
    std::cout << "[*] injection request sent successfully" << std::endl;


}

