#include "hijack.hpp"
#include "driver.hpp"
#include "util.hpp"

//#define DEBUG 1

namespace original
{
    PDRIVER_OBJECT driver_object = nullptr;
    PDRIVER_UNLOAD unload = nullptr;
    PDRIVER_DISPATCH major_functions[IRP_MJ_MAXIMUM_FUNCTION + 1] = { nullptr };
    PDEVICE_OBJECT device = nullptr;
    BOOLEAN destroy_device = FALSE;
    ULONGLONG guard_icall = 0;
}

extern "C" NTSTATUS HijackDriver(_In_ struct _DRIVER_OBJECT * driver)
{
    auto& irp_create = driver->MajorFunction[IRP_MJ_CREATE];
    auto& irp_close = driver->MajorFunction[IRP_MJ_CLOSE];
    auto& irp_device_control = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

#ifdef DEBUG
    DbgPrint("Evaluating %wZ @ 0x%p\n", &driver->DriverName, driver);
#endif

#ifdef NO_WDF
    // Check if the IRP handler are in ntoskrnl. That'd mean that they're most likely the invalid request routine.
    if (!all_hookable(driver, irp_create, irp_close, irp_device_control))
    {
#ifdef DEBUG
        DbgPrint("IRP handler(s) aren't in ntoskrnl or the current driver. Skipping.\n");
#endif
        return STATUS_INCOMPATIBLE_DRIVER_BLOCKED;
    }
#endif

    // create device
    if (driver->DeviceObject == nullptr)
    {
        const auto status = CreateSpoofedDevice(driver, &original::device);

        if(NT_ERROR(status))
        {
#ifdef DEBUG
            DbgPrint("Failed to create Device!\n");
#endif
            return status;
        }

        original::destroy_device = TRUE;   
    }
    else
    {
        const auto device_name_info = ObQueryNameInfo(driver->DeviceObject);

        if(device_name_info == nullptr)
        {
            DbgPrint("Unnamed device. Skipping.\n");
            return STATUS_NOT_IMPLEMENTED;
        }

        // cf guard fucks you over if you try to hijack existing devices
        original::guard_icall = SetCFGDispatch(driver, ULONGLONG(_ignore_icall)); 
        original::destroy_device = FALSE;
    }

    original::device = driver->DeviceObject;
   
    // backup irp handler to call original/ restore them later
    if(NT_ERROR(CopyMajorFunctions( driver->MajorFunction, original::major_functions, IRP_MJ_MAXIMUM_FUNCTION + 1)))
    {
        if(original::destroy_device == TRUE)
            DestroyDevice(&original::device);
        original::destroy_device = FALSE;
        return STATUS_COPY_PROTECTION_FAILURE;
    }

    // replace irp handlers
    irp_create = &CatchCreate;
    irp_close = &CatchClose;
    irp_device_control = &CatchDeviceCtrl;

    original::driver_object = driver;

    if(!NT_SUCCESS(CreateSymLink(original::device)))
    {
#ifdef DEBUG
        DbgPrint("Failed to create symlink\n");
#endif
    }

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
    if(NT_ERROR(CopyMajorFunctions(original::major_functions,original::driver_object->MajorFunction, IRP_MJ_MAXIMUM_FUNCTION + 1)))
    {
        // nothing we can really do here tbf
    }

    // re-enable cf guard
    SetCFGDispatch(original::driver_object, original::guard_icall);

    if (original::destroy_device == TRUE)
        DestroyDevice(&original::device);
    original::destroy_device = FALSE;
    DeleteSymLink();
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

#pragma region hooks

extern "C" void DispatchUnload(_In_ struct _DRIVER_OBJECT * driver)
{
    UnloadDriver(driver);
    RestoreDriver();
    return driver->DriverUnload(driver);
}

extern "C" NTSTATUS CallOriginal(const int idx, _In_ struct _DEVICE_OBJECT *DeviceObject, _Inout_ struct _IRP *Irp)
{
#ifdef DEBUG
    //DbgPrint("Calling original\n");
#endif
    if (original::destroy_device == TRUE)
        return STATUS_SUCCESS;

    const auto& function = original::major_functions[idx];

    if (function == nullptr)
        return STATUS_SUCCESS;
#ifdef DEBUG
    //DbgPrint("Calling original @ 0x%p\n", function);
#endif 
    return function(DeviceObject, Irp);
}

extern "C" NTSTATUS CatchCreate(PDEVICE_OBJECT device, PIRP irp)
{
    // TODO: Wipe INIT section on first IRP ;)
    return CallOriginal(IRP_MJ_CREATE, device, irp);
}

extern "C" NTSTATUS CatchClose(PDEVICE_OBJECT device, PIRP irp)
{
    return CallOriginal(IRP_MJ_CLOSE, device, irp);
}

extern "C" NTSTATUS CatchDeviceCtrl(PDEVICE_OBJECT device, PIRP irp)
{
    return CallOriginal(IRP_MJ_DEVICE_CONTROL, device, irp);
}

void UnloadDriver(PDRIVER_OBJECT)
{

}
#pragma endregion