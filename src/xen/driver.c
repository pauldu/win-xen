/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#include <ntddk.h>
#include <xen.h>
#include <util.h>

#include "fdo.h"
#include "pdo.h"
#include "driver.h"
#include "registry.h"
#include "debug.h"
#include "assert.h"
#include "version.h"

extern PULONG           InitSafeBootMode;

typedef struct XEN_DRIVER {
    PDRIVER_OBJECT          DriverObject;
    HANDLE                  ServiceKey;
    XEN_DRIVER_PARAMETERS   Parameters;
} XEN_DRIVER, *PXEN_DRIVER;

XEN_DRIVER  Driver;

PDRIVER_OBJECT
DriverGetDriverObject(
    VOID
    )
{
    return Driver.DriverObject;
}

DRIVER_UNLOAD           DriverUnload;

VOID
DriverUnload(
    IN  PDRIVER_OBJECT  _DriverObject
    )
{
    ASSERT3P(_DriverObject, ==, Driver.DriverObject);

    Trace("====>\n");

    Info("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    if (*InitSafeBootMode > 0)
        goto done;

    if (Driver.Parameters.Key != NULL) {
        RegistryCloseKey(Driver.Parameters.Key);
        Driver.Parameters.Key = NULL;
    }

    RegistryTeardown();

done:
    Driver.DriverObject = NULL;

    ASSERT(IsZeroMemory(&Driver, sizeof (XEN_DRIVER)));

    Trace("<====\n");
}

__drv_functionClass(IO_COMPLETION_ROUTINE)
__drv_sameIRQL
static NTSTATUS
DriverQueryIdCompletion(
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp,
    IN  PVOID           Context
    )
{
    PKEVENT             Event = Context;

    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static FORCEINLINE NTSTATUS
__DriverQueryId(
    IN  PDEVICE_OBJECT      PhysicalDeviceObject,
    IN  BUS_QUERY_ID_TYPE   IdType,
    OUT PVOID               *Information
    )
{
    PDEVICE_OBJECT          DeviceObject;
    PIRP                    Irp;
    KEVENT                  Event;
    PIO_STACK_LOCATION      StackLocation;
    NTSTATUS                status;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    DeviceObject = IoGetAttachedDeviceReference(PhysicalDeviceObject);

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    status = STATUS_INSUFFICIENT_RESOURCES;
    if (Irp == NULL)
        goto fail1;

    StackLocation = IoGetNextIrpStackLocation(Irp);

    StackLocation->MajorFunction = IRP_MJ_PNP;
    StackLocation->MinorFunction = IRP_MN_QUERY_ID;
    StackLocation->Flags = 0;
    StackLocation->Parameters.QueryId.IdType = IdType;
    StackLocation->DeviceObject = DeviceObject;
    StackLocation->FileObject = NULL;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IoSetCompletionRoutine(Irp,
                           DriverQueryIdCompletion,
                           &Event,
                           TRUE,
                           TRUE,
                           TRUE);

    // Default completion status
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

    status = IoCallDriver(DeviceObject, Irp);
    if (status == STATUS_PENDING) {
        (VOID) KeWaitForSingleObject(&Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        status = Irp->IoStatus.Status;
    } else {
        ASSERT3U(status, ==, Irp->IoStatus.Status);
    }

    if (!NT_SUCCESS(status))
        goto fail2;

    *Information = (PVOID)Irp->IoStatus.Information;

    IoFreeIrp(Irp);
    ObDereferenceObject(DeviceObject);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    IoFreeIrp(Irp);

fail1:
    Error("fail1 (%08x)\n", status);

    ObDereferenceObject(DeviceObject);

    return status;
}

DRIVER_ADD_DEVICE   AddDevice;

NTSTATUS
#pragma prefast(suppress:28152) // Does not clear DO_DEVICE_INITIALIZING
AddDevice(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    PANSI_STRING        ActiveDeviceInstance;
    BOOLEAN             Active;
    PWCHAR              DeviceID;
    PWCHAR              InstanceID;
    UNICODE_STRING      Unicode;
    ULONG               Length;
    NTSTATUS            status;

    ASSERT3P(_DriverObject, ==, Driver.DriverObject);

    ActiveDeviceInstance = NULL;
    if (Driver.Parameters.Key != NULL) {
        status = RegistryQuerySzValue(Driver.Parameters.Key,
                                      "ActiveDeviceInstance",
                                      &ActiveDeviceInstance);
        ASSERT(IMPLY(!NT_SUCCESS(status), ActiveDeviceInstance == NULL));
    } else {
        ActiveDeviceInstance = NULL;
    }

    Active = FALSE;

    DeviceID = NULL;
    InstanceID = NULL;

    RtlZeroMemory(&Unicode, sizeof (UNICODE_STRING));

    if (ActiveDeviceInstance == NULL)
        goto done;

    status = __DriverQueryId(DeviceObject, BusQueryDeviceID, &DeviceID);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = __DriverQueryId(DeviceObject, BusQueryInstanceID, &InstanceID);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlAnsiStringToUnicodeString(&Unicode, ActiveDeviceInstance, TRUE);
    if (!NT_SUCCESS(status))
        goto fail3;

    Length = (ULONG)wcslen(DeviceID);
    if (_wcsnicmp(Unicode.Buffer,
                  DeviceID,
                  Length) != 0)
        goto done;

    Length = (ULONG)wcslen(InstanceID);
    if (_wcsnicmp(Unicode.Buffer + (Unicode.Length / sizeof (WCHAR)) - Length,
                  InstanceID,
                  Length) != 0)
        goto done;

    Active = TRUE;

    RegistryFreeSzValue(ActiveDeviceInstance);

done:
    if (Unicode.Buffer != NULL)
        RtlFreeUnicodeString(&Unicode);

    if (InstanceID != NULL)
        ExFreePool(InstanceID);

    if (DeviceID != NULL)
        ExFreePool(DeviceID);

    status = FdoCreate(DeviceObject, Active);
    if (!NT_SUCCESS(status))
        goto fail3;

    return STATUS_SUCCESS;

fail3:
    if (InstanceID != NULL)
        ExFreePool(InstanceID);

fail2:
    if (DeviceID != NULL)
        ExFreePool(DeviceID);

fail1:
    RegistryFreeSzValue(ActiveDeviceInstance);

    Error("fail1 (%08x)\n", status);

    return status;
}

DRIVER_DISPATCH Dispatch;

NTSTATUS 
Dispatch(
    IN PDEVICE_OBJECT   DeviceObject,
    IN PIRP             Irp
    )
{
    PXEN_DX             Dx;
    NTSTATUS            status;

    Dx = (PXEN_DX)DeviceObject->DeviceExtension;
    ASSERT3P(Dx->DeviceObject, ==, DeviceObject);

    if (Dx->DevicePnpState == Deleted) {
        status = STATUS_NO_SUCH_DEVICE;

        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        goto done;
    }

    status = STATUS_NOT_SUPPORTED;
    switch (Dx->Type) {
    case PHYSICAL_DEVICE_OBJECT: {
        PXEN_PDO    Pdo = Dx->Pdo;

        status = PdoDispatch(Pdo, Irp);
        break;
    }
    case FUNCTION_DEVICE_OBJECT: {
        PXEN_FDO    Fdo = Dx->Fdo;

        status = FdoDispatch(Fdo, Irp);
        break;
    }
    default:
        ASSERT(FALSE);
        break;
    }

done:
    return status;
}

DRIVER_INITIALIZE   DriverEntry;

NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT  _DriverObject,
    IN  PUNICODE_STRING RegistryPath
    )
{
    HANDLE              ServiceKey;
    HANDLE              ParametersKey;
    ULONG               Index;
    NTSTATUS            status;

    ASSERT3P(Driver.DriverObject, ==, NULL);

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    __EnableDbgPrint();

    Trace("====>\n");

    Info("%s (%s)\n",
         MAJOR_VERSION_STR "." MINOR_VERSION_STR "." MICRO_VERSION_STR "." BUILD_NUMBER_STR,
         DAY_STR "/" MONTH_STR "/" YEAR_STR);

    Driver.DriverObject = _DriverObject;
    Driver.DriverObject->DriverUnload = DriverUnload;

    if (*InitSafeBootMode > 0)
        goto done;

    status = RegistryInitialize(RegistryPath);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenServiceKey(KEY_READ, &ServiceKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryOpenSubKey(ServiceKey, "Parameters", KEY_READ, &ParametersKey);
    if (NT_SUCCESS(status))
        Driver.Parameters.Key = ParametersKey;

    RegistryCloseKey(ServiceKey);

    Driver.DriverObject->DriverExtension->AddDevice = AddDevice;

    for (Index = 0; Index <= IRP_MJ_MAXIMUM_FUNCTION; Index++) {
#pragma prefast(suppress:28169) // No __drv_dispatchType annotation
#pragma prefast(suppress:28168) // No matching __drv_dispatchType annotation for IRP_MJ_CREATE
       Driver.DriverObject->MajorFunction[Index] = Dispatch;
    }

done:
    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    RegistryTeardown();

fail1:
    Error("fail1 (%08x)\n", status);

    Driver.DriverObject = NULL;

    ASSERT(IsZeroMemory(&Driver, sizeof (XEN_DRIVER)));

    return status;
}
