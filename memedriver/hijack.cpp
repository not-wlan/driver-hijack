#include "hijack.hpp"

#include "hooks.hpp"

namespace original
{
    PDRIVER_OBJECT driver_object = nullptr;
    PDRIVER_UNLOAD unload = nullptr;
    PDRIVER_DISPATCH major_functions[IRP_MJ_MAXIMUM_FUNCTION + 1] = { nullptr };
    PDEVICE_OBJECT device = nullptr;
}

extern "C" NTSTATUS GetModule(IN const PUNICODE_STRING name, OUT PKLDR_DATA_TABLE_ENTRY* out_entry)
{
    if (name == nullptr)
        return STATUS_INVALID_PARAMETER;

    if (IsListEmpty(PsLoadedModuleList))
        return STATUS_NOT_FOUND;

    for (auto list_entry = PsLoadedModuleList->Flink; list_entry != PsLoadedModuleList; list_entry = list_entry->Flink)
    {
        auto entry = CONTAINING_RECORD(list_entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (RtlCompareUnicodeString(&entry->BaseDllName, name, TRUE) == 0)
        {
            *out_entry = entry;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

extern "C" NTSTATUS GetNtoskrnl(OUT PKLDR_DATA_TABLE_ENTRY* out_entry)
{
    if (IsListEmpty(PsLoadedModuleList))
        return STATUS_NOT_FOUND;
    *out_entry = CONTAINING_RECORD(PsLoadedModuleList, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return STATUS_SUCCESS;
}

extern "C" bool IsInNtoskrnl(PVOID address)
{
    PKLDR_DATA_TABLE_ENTRY entry = nullptr;

    if (!NT_SUCCESS(GetNtoskrnl(&entry)))
    {
#ifdef DEBUG
        DbgPrint("Failed to get ntoskrnl\n");
#endif
        return false;
    }
#ifdef DEBUG
    DbgPrint("Module: %wZ\n", &entry->BaseDllName);
#endif
    return uintptr_t(address) >= uintptr_t(entry->DllBase) && uintptr_t(address) <= (uintptr_t(entry->DllBase) + entry->SizeOfImage);
}

extern "C" NTSTATUS HijackDriver(_In_ struct _DRIVER_OBJECT * driver)
{
    auto& irp_create = driver->MajorFunction[IRP_MJ_CREATE];
    auto& irp_close = driver->MajorFunction[IRP_MJ_CLOSE];
    auto& irp_device_control = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
#ifdef DEBUG
    DbgPrint("Evaluating %wZ @ 0x%p\n", &driver->DriverName, driver);
#endif
    // Check if the IRP handler are in ntoskrnl. That'd mean that they're most likely the invalid request routine.
    if (!all_in_ntoskrnl(irp_create, irp_close, irp_device_control))
    {
#ifdef DEBUG
        DbgPrint("IRP handler aren't in ntoskrnl. Skipping.\n");
#endif
        return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
    }

    if (driver->DeviceObject != nullptr)
    {
#ifdef DEBUG
        DbgPrint("Driver already has a device. Skipping.");
#endif
        return STATUS_DEVICE_ALREADY_ATTACHED;
    }

    UNICODE_STRING device_name{}, dos_device_name{};

    RtlInitUnicodeString(&device_name, memedriver::device_name);
    RtlInitUnicodeString(&dos_device_name, memedriver::dos_device_name);

    // Create spoofed device
    // TODO: hijack existing device instead?
    auto status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_KS, FILE_DEVICE_SECURE_OPEN, FALSE, &original::device);

    if (!NT_SUCCESS(status))
    {
        original::device = nullptr;
#ifdef DEBUG
        DbgPrint("Failed to create a spoofed device. Skipping.\n");
#endif
        return status;
    }

    status = IoCreateSymbolicLink(&dos_device_name, &device_name);

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(original::device);
        original::device = nullptr;
#ifdef DEBUG
        DbgPrint("Failed to create symlink for spoofed device. Skipping.\n");
#endif
        return status;
    }

    // Finish off initialization by setting flags
    original::device->Flags &= ~DO_DEVICE_INITIALIZING;
    original::device->Flags |= DO_BUFFERED_IO;

    original::major_functions[IRP_MJ_CREATE] = irp_create;
    original::major_functions[IRP_MJ_CLOSE] = irp_close;
    original::major_functions[IRP_MJ_DEVICE_CONTROL] = irp_device_control;

    irp_create = &CatchCreate;
    irp_close = &CatchClose;
    irp_device_control = &CatchDeviceCtrl;

    original::driver_object = driver;

    // Windows interprets no unload routine as can't be unloaded so it wouldn't be benefitial to add an unload routine to a driver that doesn't support it.
    if (driver->DriverUnload != nullptr) {
        original::unload = driver->DriverUnload;
        driver->DriverUnload = &DispatchUnload;
    }
#ifdef DEBUG
    DbgPrint("Successfully hooked %wZ @ 0x%p\n", &driver->DriverName, driver);
#endif
    return STATUS_SUCCESS;
}

extern "C" VOID RestoreDriver()
{
    if (original::driver_object == nullptr)
        return;

    if (original::unload != nullptr)
    {
        original::driver_object->DriverUnload = original::unload;
        original::unload = nullptr;
    }

    // restore irp handlers
    auto& major_functions = original::driver_object->MajorFunction;

    major_functions[IRP_MJ_CREATE] = original::major_functions[IRP_MJ_CREATE];
    major_functions[IRP_MJ_CLOSE] = original::major_functions[IRP_MJ_CLOSE];
    major_functions[IRP_MJ_DEVICE_CONTROL] = original::major_functions[IRP_MJ_DEVICE_CONTROL];

    UNICODE_STRING dos_device_name{};
    RtlInitUnicodeString(&dos_device_name, memedriver::dos_device_name);

    if (NT_ERROR(IoDeleteSymbolicLink(&dos_device_name)))
    {
#ifdef DEBUG
        DbgPrint("Failed to delete Symbolic link!\n");
#endif
    }

    IoDeleteDevice(original::device);
    original::device = nullptr;

    original::driver_object = nullptr;
}

extern "C" NTSTATUS FindDriver(_In_ struct _DRIVER_OBJECT * ignore /*= nullptr*/)
{
    HANDLE handle{};
    OBJECT_ATTRIBUTES attributes{};
    UNICODE_STRING directory_name{};
    PVOID directory{};
    BOOLEAN success = FALSE;

    RtlInitUnicodeString(&directory_name, L"\\Driver");
    InitializeObjectAttributes(&attributes, &directory_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // open OBJECT_DIRECTORY for \Driver
    auto status = ZwOpenDirectoryObject(&handle, DIRECTORY_ALL_ACCESS, &attributes);

    if (!NT_SUCCESS(status))
        return status;

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

        if (success == TRUE)
            break;

        while (entry != nullptr && entry->Object != nullptr)
        {
            // You could add type checking here with ObGetObjectType but if that's wrong we're gonna bsod anyway :P
            auto driver = PDRIVER_OBJECT(entry->Object);

            if (ignore != nullptr)
            {
                if (RtlCompareUnicodeString(&driver->DriverName, &ignore->DriverName, FALSE) == 0)
                {
                    entry = entry->ChainLink;
                    continue;
                }
            }

            if (NT_SUCCESS(HijackDriver(driver)))
            {
                success = TRUE;
                break;
            }

            entry = entry->ChainLink;
        }

    }

    ExReleasePushLockExclusiveEx(&directory_object->Lock, 0);

    // Release the acquired resources back to the OS
    ObDereferenceObject(directory);
    ZwClose(handle);

    return success == TRUE ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

extern "C" VOID PrintInfo()
{
#ifdef DEBUG
    DbgPrint("Hijacked Driver: %wZ @ 0x%p\n", &original::driver_object->DriverName, original::driver_object);
#endif
}

void DispatchUnload(_In_ struct _DRIVER_OBJECT * driver)
{
    UnloadDriver(driver);
    RestoreDriver();
    return driver->DriverUnload(driver);
}

