#include "hijack.hpp"
#include "memedriver.hpp"

#pragma comment(lib, "ntoskrnl.lib")


extern "C" __declspec(dllexport) VOID DriverUnload(_In_ struct _DRIVER_OBJECT *)
{
    RestoreDriver();
#ifdef DEBUG
    DbgPrint("MEMEDriver unloaded!\n");
#endif
}

extern "C" NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT * DriverObject, PUNICODE_STRING)
{
    if(DriverObject != nullptr)
    {
        DriverObject->DriverUnload = DriverUnload;
    }

    if(NT_SUCCESS(FindDriver(DriverObject)))
    {
        PrintInfo();
        return STATUS_SUCCESS;
    }

    return STATUS_FAILED_DRIVER_ENTRY;
}

