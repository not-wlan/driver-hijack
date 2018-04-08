#pragma once
#include <ntddk.h>

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) extern "C" NTSTATUS CatchDeviceCtrl(PDEVICE_OBJECT, PIRP);
_Dispatch_type_(IRP_MJ_CREATE) extern "C" NTSTATUS CatchCreate(PDEVICE_OBJECT, PIRP);
_Dispatch_type_(IRP_MJ_CLOSE) extern "C"  NTSTATUS CatchClose(PDEVICE_OBJECT, PIRP);
extern "C" VOID UnloadDriver(PDRIVER_OBJECT);

#pragma alloc_text(NONPAGED, CatchDeviceCtrl)
#pragma alloc_text(NONPAGED, CatchCreate)
#pragma alloc_text(NONPAGED, CatchClose)
#pragma alloc_text(NONPAGED, UnloadDriver)
