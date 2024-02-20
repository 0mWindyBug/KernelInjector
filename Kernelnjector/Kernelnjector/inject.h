#pragma once
#include <main.h>


#define ALERTABLE 0x1 
#define KTHREAD_FLAGS_OFFSET 0x74 
#define ALERTABLE_BIT 4 




NTSTATUS Inject(PINJECTION_INFO InjectionInfo);

extern unsigned char load_dll_shellcode[331];
