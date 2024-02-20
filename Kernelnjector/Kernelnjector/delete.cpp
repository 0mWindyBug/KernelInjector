#include <main.h>

void __cdecl operator delete(void* address, unsigned __int64)
{
	::ExFreePool(address);
}