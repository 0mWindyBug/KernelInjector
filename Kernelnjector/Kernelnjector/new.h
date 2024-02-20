#pragma once
#include <main.h>

void* __cdecl operator new(size_t size, POOL_TYPE pool_type, ULONG tag = 0);