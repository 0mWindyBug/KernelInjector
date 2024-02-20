#include <main.h>


void* __cdecl operator new(size_t size, POOL_TYPE pool_type, ULONG tag)
{
	auto address = ::ExAllocatePoolWithTag(
		pool_type,
		size,
		tag
	);

	return address;
}