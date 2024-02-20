#include <main.h>


extern "C" PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

PVOID FindSymbolAdddress(BYTE* module_address, char* symbol_name) {
	auto dos_header = (IMAGE_DOS_HEADER*)module_address;
	auto nt_headers64 = (IMAGE_NT_HEADERS64*)(module_address + dos_header->e_lfanew);
	auto optional_header = (IMAGE_OPTIONAL_HEADER64*)&nt_headers64->OptionalHeader;
	auto export_directory = &optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	auto export_table = (IMAGE_EXPORT_DIRECTORY*)(module_address + export_directory->VirtualAddress);
	for (size_t i = 0; i < export_table->NumberOfNames; i++) {
		auto function_name_offset = *(ULONG*)(module_address + export_table->AddressOfNames + (sizeof(export_table->AddressOfNames) * i));
		auto function_name = (char*)module_address + (size_t)function_name_offset;
		if (0 == strcmp(function_name, symbol_name)) {
			return module_address + *(ULONG*)(module_address + export_table->AddressOfFunctions + (sizeof(export_table->AddressOfFunctions) * i));
		}
	}
	return nullptr;
}

PVOID GetExportAddress(wchar_t* module_name, char* symbol_name) {
	PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
	auto module_entry = (LDR_DATA_TABLE_ENTRY*)((char*)peb->Ldr->InLoadOrderModuleList.Flink);
	do {
		if (nullptr != wcsstr(module_entry->FullDllName.Buffer, module_name)) {
			return FindSymbolAdddress((BYTE*)module_entry->DllBase, symbol_name);
		}
		module_entry = (LDR_DATA_TABLE_ENTRY*)((char*)module_entry->InLoadOrderLinks.Flink);
	} while (module_entry != nullptr);
	return nullptr;
}