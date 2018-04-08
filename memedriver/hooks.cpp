#include "hooks.hpp"

extern "C" NTSTATUS CatchCreate(PDEVICE_OBJECT, PIRP)
{
    // TODO: Wipe INIT section on first IRP ;)
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

void UnloadDriver(PDRIVER_OBJECT)
{

}
