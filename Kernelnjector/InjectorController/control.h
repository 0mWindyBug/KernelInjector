#pragma once
#include <main.h>

#define IOCTL_DLL_INJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define TARGET_DEVICE L"\\\\.\\kinjector"

typedef struct _INJECTION_INFO
{
	ULONG TargetPid;
}INJECTION_INFO, * PINJECTION_INFO;

bool SendInjectionRequest(PINJECTION_INFO InjectionInfo);