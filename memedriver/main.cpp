#include "memedriver.hpp"
#pragma comment(lib, "ntoskrnl.lib")

namespace memedriver {
    // Hooked unload routine
    decltype(&DriverUnload) original_unload = nullptr;
    // Hijacked driver object
    PDRIVER_OBJECT hooked_driver = nullptr;
    // Flag to define if we were manual mapped
    ULONG manual_mapped = 0;
}

extern "C" VOID HookedUnloadDriver(PDRIVER_OBJECT driver)
{
    driver->DriverUnload = memedriver::original_unload;
    memedriver::original_unload = nullptr;
    DbgPrint("We in it to win it!\n");
    return driver->DriverUnload(driver);
}

extern "C" NTSTATUS FindDriver(PDRIVER_OBJECT* hooked_driver) {
    HANDLE handle{};
    OBJECT_ATTRIBUTES attributes{};
    UNICODE_STRING directory_name{};
    PVOID Directory{};
    UINT32 HookableDrivers{};

    if (hooked_driver == nullptr)
        return STATUS_INVALID_PARAMETER;
    *hooked_driver = nullptr;

    RtlInitUnicodeString(&directory_name, L"\\Driver");
    InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // open OBJECT_DIRECTORY for \Driver
    auto status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

    if (!NT_SUCCESS(status))
        return status;

    DbgPrint("Opened \\Driver Directory Handle 0x%p\n", handle);

    // Get OBJECT_DIRECTORY pointer from HANDLE
    status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &Directory, nullptr);

    if (!NT_SUCCESS(status)) {
        ZwClose(handle);
        return status;
    }

    const auto directory = POBJECT_DIRECTORY(Directory);
    // Traverse entry tree
    for (auto entry : directory->HashBuckets)
    {
        if (entry == nullptr)
            continue;

        while (entry->Object != nullptr)
        {
            // You could add type checking here with ObGetObjectType but if that's wrong we're gonna bsod anyway :P
            auto driver = PDRIVER_OBJECT(entry->Object);

            DbgPrint("%wZ -> 0x%p\n", &driver->DriverName, driver);

            if (driver->DriverUnload != nullptr)
            {
                auto& close_irp = driver->MajorFunction[IRP_MJ_CLOSE];
                auto& open_irp = driver->MajorFunction[IRP_MJ_CREATE];
                auto& device_io_irp = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

                // Check if IRP_MJ_CLOSE, IRP_MJ_CREATE and IRP_MJ_DEVICE_CONTROL point to the same address
                // and are outside of the module
                if(uintptr_t(close_irp) == uintptr_t(open_irp) && uintptr_t(open_irp) == uintptr_t(device_io_irp))
                {
                    const auto base = uintptr_t(driver->DriverSection);
                    const auto max = base + driver->Size;

                    if(uintptr_t(close_irp) < base || uintptr_t(close_irp) > max)
                    {
                        DbgPrint("Hookable Driver %wZ found!\n", &driver->DriverName);
                        HookableDrivers++;
                    }

                }
                // Hook unload routine
                if (memedriver::original_unload == nullptr)
                {
                    DbgPrint("Hooking unload of %wZ!\n", &driver->DriverName);
                    memedriver::original_unload = driver->DriverUnload;
                    driver->DriverUnload = &HookedUnloadDriver;

                    *hooked_driver = driver;
                }
            }

            entry = entry->ChainLink;
            if (entry == nullptr)
                break;
        }

    }

    // Release the acquired resources back to the OS
    ObDereferenceObject(directory);
    ZwClose(handle);

    DbgPrint("%lu hookable drivers found\n", HookableDrivers);

    return STATUS_SUCCESS;
}

extern "C" __declspec(dllexport) VOID DriverUnload(_In_ struct _DRIVER_OBJECT *)
{

    if (memedriver::original_unload != nullptr && memedriver::hooked_driver != nullptr)
    {
        DbgPrint("Unhooking Unload Routine\n");
        memedriver::hooked_driver->DriverUnload = memedriver::original_unload;
    }

    DbgPrint("MEMEDriver unloaded!\n");
}

extern "C" NTSTATUS DriverInitialize(_In_ struct _DRIVER_OBJECT * DriverObject, PUNICODE_STRING)
{
    if (memedriver::manual_mapped == 0)
    {
        // Disable Unload Routine when manual mapped since the system won't call it anyway.
        DriverObject->DriverUnload = DriverUnload;
    }

    DbgPrint("DriverObject: 0x%p\n", DriverObject);

    if (NT_SUCCESS(FindDriver(&memedriver::hooked_driver)))
    {
        DbgPrint("Successfully hijacked driver!\n");

        // returning anything but a successful NTSTATUS will lead to the unloading of the driver and won't create a entry in MmUnloadedDrivers
        return STATUS_SUCCESS;
    }

    return STATUS_FAILED_DRIVER_ENTRY;
}

extern "C" NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath)
{
    if (DriverObject == nullptr)
    {
        // We've been manualmapped!
        memedriver::manual_mapped = 1;
        return IoCreateDriver(RegistryPath, DriverInitialize);
    }

    DbgPrint("Loading MEMEDriver regularly\n");
    // Continue as normal
    return DriverInitialize(DriverObject, RegistryPath);
}