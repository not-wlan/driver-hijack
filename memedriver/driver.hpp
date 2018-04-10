#pragma once
#include <ntifs.h>
#include <ntddk.h>

#define DEVICE_NAME(name) L"\\Device\\"#name
#define DOSDEVICE_NAME(name) L"\\DosDevices\\"#name
#define DRIVER_NAME(name) L"\\Driver\\"#name

namespace memedriver
{
    constexpr auto device_name = DEVICE_NAME(meme);
    constexpr auto dos_device_name = DOSDEVICE_NAME(meme);
}

extern "C" NTSTATUS CreateSpoofedDevice(_In_ struct _DRIVER_OBJECT * driver, _Out_ PDEVICE_OBJECT* device);
extern "C" VOID DestroyDevice(PDEVICE_OBJECT* device);
extern "C" NTSTATUS DeleteSymLink();
extern "C" NTSTATUS CreateSymLink(PDEVICE_OBJECT device);