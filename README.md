# KernelInjector
PoC kernel to usermode dll injection 

Tested on Windows 10 22H2

# Usage 
InjectorController.exe <target_pid>

the shellcode is injecting "C:\\hooking.dll" so make sure to rename your dll or modify the shellcode accordingly 

see load_dll_shellcode.asm provided source file 

# How it works 
1. KeStackAttachProcess to attach to the received target process address space (CR3)
2. RX allocation for our shellcode using ZwAllocateVirtualMemory 
3. MmMapLockedPagesSpecifyCache & MmProtectMdlSystemAddress to create another mapping for our shellcode allocation and set it to RW (thus avoiding allocation of RWX memory) 
4. Copy shellcode to RW Mdl mapping
5. Enumerate the process's threads list and find an alertable thread (indicated by the Alertable flag in the KTHREAD structure)
6. Queue a user apc to the target address with the normal routine pointing at our shellcode
7. Shellcode executes and calls LoadLibraryA to load our module (could be improved to signal an event so the driver can free it once it finishes executing)

# Detection vectors and things to consider 
* shellcode resides within an executable allocation not backed by a module on disk (potential workaround would be to find a code cave in a loaded module and write the shellcode there) 
* shellcode can be memory scanned
* LoadLibrary or LdrLoadDLL might be hooked and monitored
* Drivers that register to image load notify routines or filter on IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION will be aware we loaded a module
* In case of Anti Cheat or AV processes they can walk the peb or use EnumProcessModules to identify 'unknown' DLLs in their process 
* User APC dispatcher can be hooked 
