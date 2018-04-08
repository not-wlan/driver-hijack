#include "memedriver.hpp"
#pragma comment(lib, "ntoskrnl.lib")

namespace memedriver {
    constexpr auto device_name = DEVICE_NAME(meme);
    constexpr auto dos_device_name = DOSDEVICE_NAME(meme);

    // Hooked unload routine
    decltype(&DriverUnload) original_unload = nullptr;
    // Hijacked driver object
    PDRIVER_OBJECT hooked_driver = nullptr;
    // Flag to define if we were manual mapped
    ULONG manual_mapped = 0;

    PDEVICE_OBJECT device = nullptr;

    PDRIVER_DISPATCH original_irp_handler = nullptr;
}

extern "C" VOID HookedUnloadDriver(DRIVER_OBJECT* driver)
{
    driver->DriverUnload = memedriver::original_unload;
    memedriver::original_unload = nullptr;
    DbgPrint("We in it to win it!\n");

    if(NT_SUCCESS(DestroyDevice()))
    {
        DbgPrint("Successfully destroyed device!\n");
    }

    if(NT_SUCCESS(RestoreIRPHandler()))
    {
        DbgPrint("Successfully restored IRP handlers!");
    }

    if(driver->DriverUnload != nullptr)
        return driver->DriverUnload(driver);
}

extern "C" NTSTATUS DestroyDevice()
{
    if (memedriver::device == nullptr)
        return STATUS_SUCCESS;

    UNICODE_STRING dos_device_name{};

    RtlInitUnicodeString(&dos_device_name, memedriver::dos_device_name);
    
    if(!NT_SUCCESS(IoDeleteSymbolicLink(&dos_device_name)))
    {
        DbgPrint("Failed to remove symbolic link!");
        return STATUS_CANNOT_DELETE;
    }

    IoDeleteDevice(memedriver::device);
    memedriver::device = nullptr;

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS RestoreIRPHandler()
{
    if (memedriver::device == nullptr || memedriver::hooked_driver == nullptr || memedriver::original_irp_handler == nullptr)
        return STATUS_SUCCESS;

    auto& major_functions = memedriver::hooked_driver->MajorFunction;

    major_functions[IRP_MJ_CREATE] = memedriver::original_irp_handler;
    major_functions[IRP_MJ_CLOSE] = memedriver::original_irp_handler;
    major_functions[IRP_MJ_DEVICE_CONTROL] = memedriver::original_irp_handler;

    memedriver::original_irp_handler = nullptr;

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS CatchCreate(PDEVICE_OBJECT, PIRP)
{
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS CatchClose(PDEVICE_OBJECT, PIRP)
{
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS CatchDeviceCtrl(PDEVICE_OBJECT, PIRP)
{
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS FindDriver(PDRIVER_OBJECT* hooked_driver, PDRIVER_OBJECT Ignore) {
    HANDLE handle{};
    OBJECT_ATTRIBUTES attributes{};
    UNICODE_STRING directory_name{};
    UNICODE_STRING device_name{};
    UNICODE_STRING dos_device_name{};
    PVOID directory{};
    
    if (hooked_driver == nullptr)
        return STATUS_INVALID_PARAMETER;
    *hooked_driver = nullptr;

    RtlInitUnicodeString(&device_name, memedriver::device_name);
    RtlInitUnicodeString(&dos_device_name, memedriver::dos_device_name);
    RtlInitUnicodeString(&directory_name, L"\\Driver");
    InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // open OBJECT_DIRECTORY for \Driver
    auto status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

    if (!NT_SUCCESS(status))
        return status;

    DbgPrint("Opened \\Driver Directory Handle 0x%p\n", handle);

    // Get OBJECT_DIRECTORY pointer from HANDLE
    status = ObReferenceObjectByHandle(handle, DIRECTORY_ALL_ACCESS, nullptr, KernelMode, &directory, nullptr);

    if (!NT_SUCCESS(status)) {
        ZwClose(handle);
        return status;
    }

    const auto directory_object = POBJECT_DIRECTORY(directory);

    ExAcquirePushLockExclusiveEx(&directory_object->Lock, 0);

    // Traverse entry tree
    for (auto entry : directory_object->HashBuckets)
    {
        if (entry == nullptr)
            continue;

        if (*hooked_driver != nullptr)
            break;

        while (entry->Object != nullptr)
        {
            // You could add type checking here with ObGetObjectType but if that's wrong we're gonna bsod anyway :P
            auto driver = PDRIVER_OBJECT(entry->Object);

            if(driver == Ignore || RtlCompareUnicodeString(&driver->DriverName, &Ignore->DriverName, FALSE) == 0)
            {
                DbgPrint("Skipping %wZ\n", &driver->DriverName);
                entry = entry->ChainLink;
                if (entry == nullptr)
                    break;
                continue;
            }

            //DbgPrint("Checking %wZ @ 0x%p\n", &driver->DriverName, driver);

            if (driver->DriverUnload != nullptr)
            {
                auto& close_irp = driver->MajorFunction[IRP_MJ_CLOSE];
                auto& open_irp = driver->MajorFunction[IRP_MJ_CREATE];
                auto& device_io_irp = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

                // Check if IRP_MJ_CLOSE, IRP_MJ_CREATE and IRP_MJ_DEVICE_CONTROL point to the same address
                // and are outside of the module
                if(uintptr_t(close_irp) == uintptr_t(open_irp) && uintptr_t(open_irp) == uintptr_t(device_io_irp) && driver->DeviceObject == nullptr)
                {
                    const auto base = uintptr_t(driver->DriverSection);
                    const auto max = base + driver->Size;

                    if(uintptr_t(close_irp) < base || uintptr_t(close_irp) > max)
                    {
                        DbgPrint("Hooking into %wZ @ 0x%p\n", &driver->DriverName, driver);

                        if(!NT_SUCCESS(IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_KS, FILE_DEVICE_SECURE_OPEN, 0, &memedriver::device)))
                        {
                            DbgPrint("[%wZ] Failed to create hijacked device!\n", &driver->DriverName);
                            memedriver::device = nullptr;
                            entry = entry->ChainLink;
                            if (entry == nullptr)
                                break;

                            continue;
                        }

                        if(!NT_SUCCESS(IoCreateSymbolicLink(&dos_device_name, &device_name)))
                        {
                            DbgPrint("[%wZ] Failed to create hijacked device symlink!\n", &driver->DriverName);
                            
                            IoDeleteDevice(memedriver::device);

                            memedriver::device = nullptr;
                            entry = entry->ChainLink;
                            if (entry == nullptr)
                                break;

                            continue;
                        }

                        DbgPrint("[%wZ] Created symlink [%wZ] -> [%wZ]\n", &driver->DriverName, &device_name, &dos_device_name);

                        memedriver::device->Flags &= ~DO_DEVICE_INITIALIZING;
                        memedriver::device->Flags |= DO_BUFFERED_IO;

                        memedriver::original_irp_handler = close_irp;

                        close_irp = CatchClose;
                        open_irp = CatchCreate;
                        //device_io_irp = CatchDeviceCtrl;

                        // Hook unload routine 
                        if (memedriver::original_unload == nullptr)
                        {
                            DbgPrint("Hooking unload of %wZ!\n", &driver->DriverName);
                            memedriver::original_unload = driver->DriverUnload;
                            driver->DriverUnload = &HookedUnloadDriver;
                        }

                        DbgPrint("Hooked %wZ\n", &driver->DriverName);

                        *hooked_driver = driver;
                        break;
                    }

                }

            }

            entry = entry->ChainLink;
            if (entry == nullptr)
                break;
        }

    }

    ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);

    // Release the acquired resources back to the OS
    ObDereferenceObject(directory);
    ZwClose(handle);

    return STATUS_SUCCESS;
}

extern "C" __declspec(dllexport) VOID DriverUnload(_In_ struct _DRIVER_OBJECT *)
{

    if (memedriver::original_unload != nullptr && memedriver::hooked_driver != nullptr)
    {
        DbgPrint("Unhooking Unload Routine\n");
        memedriver::hooked_driver->DriverUnload = memedriver::original_unload;
    }

    if (NT_SUCCESS(DestroyDevice()))
    {
        DbgPrint("Successfully destroyed device!\n");
    }

    if (NT_SUCCESS(RestoreIRPHandler()))
    {
        DbgPrint("Successfully restored IRP handlers!\n");
    }

    DbgPrint("MEMEDriver unloaded!\n");
}

extern "C" NTSTATUS DriverInitialize(_In_ struct _DRIVER_OBJECT * DriverObject, PUNICODE_STRING)
{
    if(DriverObject != nullptr)
    {
        DriverObject->DriverUnload = DriverUnload;
    }

    if (NT_SUCCESS(FindDriver(&memedriver::hooked_driver, DriverObject)))
    {
        DbgPrint("Successfully hijacked driver %wZ!\n", &memedriver::hooked_driver->DriverName);

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
    }

    DbgPrint("Loading MEMEDriver regularly\n");
    // Continue as normal
    return DriverInitialize(DriverObject, RegistryPath);
}