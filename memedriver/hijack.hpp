#pragma once
#include "structs.hpp"

#define DEVICE_NAME(name) L"\\Device\\"#name
#define DOSDEVICE_NAME(name) L"\\DosDevices\\"#name
#define DRIVER_NAME(name) L"\\Driver\\"#name

namespace memedriver
{
    constexpr auto device_name = DEVICE_NAME(meme);
    constexpr auto dos_device_name = DOSDEVICE_NAME(meme);
}


extern "C" NTSTATUS GetModule(IN PUNICODE_STRING name, OUT PKLDR_DATA_TABLE_ENTRY* out_entry);
extern "C" NTSTATUS GetNtoskrnl(OUT PKLDR_DATA_TABLE_ENTRY* out_entry);
extern "C" bool IsInNtoskrnl(PVOID address);
extern "C" NTSTATUS HijackDriver(PDRIVER_OBJECT driver);
extern "C" NTSTATUS FindDriver(PDRIVER_OBJECT ignore = nullptr);
extern "C" VOID PrintInfo();

extern "C" VOID DispatchUnload(PDRIVER_OBJECT);
extern "C" VOID RestoreDriver();

#pragma alloc_text(INIT, HijackDriver)
#pragma alloc_text(INIT, IsInNtoskrnl)
#pragma alloc_text(INIT, GetNtoskrnl)
#pragma alloc_text(INIT, GetModule)
#pragma alloc_text(INIT, FindDriver)
#pragma alloc_text(INIT, PrintInfo)

#pragma alloc_text(NONPAGED, RestoreDriver)

template<typename... Args>
bool all_in_ntoskrnl(Args... args) { return (... && IsInNtoskrnl(args)); }
