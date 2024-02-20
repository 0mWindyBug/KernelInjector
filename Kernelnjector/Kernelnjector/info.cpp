#include <main.h>

PVOID get_all_processes() {
    size_t processes_allocation_size = 0;
    PVOID processes_pool = nullptr;

    while (true) {
        processes_allocation_size += 0x10000;
        processes_pool = ExAllocatePool(PagedPool, processes_allocation_size);

        auto status = ZwQuerySystemInformation(SystemProcessInformation, processes_pool, (ULONG)processes_allocation_size, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            ExFreePool(processes_pool);
        }
        else {
            break;
        }
    }
    return processes_pool;
}

NTSTATUS get_process_info_by_pid(size_t pid, ProcessInfo* process_info) {
    size_t number_of_processes = 0;
    ProcessInfo* processes = get_processes_info(&number_of_processes);
    if (nullptr == processes) {
        return STATUS_UNSUCCESSFUL;
    }
    for (size_t i = 0; i < number_of_processes; i++) {
        if (pid == (processes + i)->process_id) {
            *process_info = *(processes + i);
            (processes + i)->threads_id = nullptr;
        }
    }
    for (size_t i = 0; i < number_of_processes; i++) {
        if (nullptr != (processes + i)->threads_id && (processes + i)->number_of_threads > 0) {
            ExFreePool((processes + i)->threads_id);
        }
    }
    ExFreePool(processes);
    return STATUS_SUCCESS;
}

ProcessInfo* get_processes_info(size_t* number_of_processes) {
    PVOID all_processes = get_all_processes();
    if (nullptr == all_processes) {
        return nullptr;
    }
    *number_of_processes = 0;
    for (auto process = (SYSTEM_PROCESS_INFORMATION*)all_processes; process->NextEntryOffset != 0;
        process = (SYSTEM_PROCESS_INFORMATION*)((char*)process + process->NextEntryOffset)) {
        *number_of_processes += 1;
    }

    auto processes_info = (ProcessInfo*)ExAllocatePool(PagedPool, sizeof(ProcessInfo) * *number_of_processes);

    size_t i = 0;
    for (auto process = (SYSTEM_PROCESS_INFORMATION*)all_processes; process->NextEntryOffset != 0;
        process = (SYSTEM_PROCESS_INFORMATION*)((char*)process + process->NextEntryOffset), ++i) {
        (processes_info + i)->process_id = (size_t)process->ProcessId;
        (processes_info + i)->number_of_threads = (size_t)process->NumberOfThreads;
        if (0 == process->NumberOfThreads) {
            continue;
        }
        (processes_info + i)->threads_id = (size_t*)ExAllocatePool(PagedPool, sizeof(size_t) * process->NumberOfThreads);
        for (size_t j = 0; j < process->NumberOfThreads; j++) {
            *(((ProcessInfo*)(processes_info + i))->threads_id + j) = (size_t)process->Threads[j].ClientId.UniqueThread;
        }
    }

    ExFreePool(all_processes);
    return processes_info;
}