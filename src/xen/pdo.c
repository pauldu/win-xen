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

#define INITGUID 1

#include <ntddk.h>
#include <wdmguid.h>
#include <ntstrsafe.h>
#include <util.h>

#include <hypercall_interface.h>

#include "names.h"
#include "fdo.h"
#include "pdo.h"
#include "bus.h"
#include "driver.h"
#include "thread.h"
#include "registry.h"
#include "log.h"
#include "assert.h"

#define PDO_TAG 'ODP'

struct _XEN_PDO {
    PXEN_DX                     Dx;

    PXEN_THREAD                 SystemPowerThread;
    PIRP                        SystemPowerIrp;
    PXEN_THREAD                 DevicePowerThread;
    PIRP                        DevicePowerIrp;

    PXEN_FDO                    Fdo;
    BOOLEAN                     Missing;
    const CHAR                  *Reason;
    ULONG                       Revision;

    BUS_INTERFACE_STANDARD      BusInterface;
};

static FORCEINLINE PVOID
__PdoAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, PDO_TAG);
}

static FORCEINLINE VOID
__PdoFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, PDO_TAG);
}

static FORCEINLINE VOID
__PdoSetDevicePnpState(
    IN  PXEN_PDO            Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXEN_DX                 Dx = Pdo->Dx;

    // We can never transition out of the deleted state
    ASSERT(Dx->DevicePnpState != Deleted || State == Deleted);

    Dx->PreviousDevicePnpState = Dx->DevicePnpState;
    Dx->DevicePnpState = State;
}

VOID
PdoSetDevicePnpState(
    IN  PXEN_PDO            Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    __PdoSetDevicePnpState(Pdo, State);
}

static FORCEINLINE VOID
__PdoRestoreDevicePnpState(
    IN  PXEN_PDO            Pdo,
    IN  DEVICE_PNP_STATE    State
    )
{
    PXEN_DX                 Dx = Pdo->Dx;

    if (Dx->DevicePnpState == State)
        Dx->DevicePnpState = Dx->PreviousDevicePnpState;
}

static FORCEINLINE DEVICE_PNP_STATE
__PdoGetDevicePnpState(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_DX         Dx = Pdo->Dx;

    return Dx->DevicePnpState;
}

DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXEN_PDO    Pdo
    )
{
    return __PdoGetDevicePnpState(Pdo);
}

static FORCEINLINE VOID
__PdoSetDevicePowerState(
    IN  PXEN_PDO            Pdo,
    IN  DEVICE_POWER_STATE  State
    )
{
    PXEN_DX                 Dx = Pdo->Dx;

    Dx->DevicePowerState = State;
}

static FORCEINLINE DEVICE_POWER_STATE
__PdoGetDevicePowerState(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_DX         Dx = Pdo->Dx;

    return Dx->DevicePowerState;
}

static FORCEINLINE VOID
__PdoSetSystemPowerState(
    IN  PXEN_PDO            Pdo,
    IN  SYSTEM_POWER_STATE  State
    )
{
    PXEN_DX                 Dx = Pdo->Dx;

    Dx->SystemPowerState = State;
}

static FORCEINLINE SYSTEM_POWER_STATE
__PdoGetSystemPowerState(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_DX         Dx = Pdo->Dx;

    return Dx->SystemPowerState;
}

static FORCEINLINE VOID
__PdoSetMissing(
    IN  PXEN_PDO    Pdo,
    IN  const CHAR  *Reason
    )
{
    Pdo->Reason = Reason;
    Pdo->Missing = TRUE;
}

VOID
PdoSetMissing(
    IN  PXEN_PDO    Pdo,
    IN  const CHAR  *Reason
    )
{
    __PdoSetMissing(Pdo, Reason);
}

static FORCEINLINE BOOLEAN
__PdoIsMissing(
    IN  PXEN_PDO    Pdo
    )
{
    return Pdo->Missing;
}

BOOLEAN
PdoIsMissing(
    IN  PXEN_PDO    Pdo
    )
{
    return __PdoIsMissing(Pdo);
}

static FORCEINLINE NTSTATUS
__PdoSetRevision(
    IN  PXEN_PDO    Pdo
    )
{
    HANDLE          ServiceKey;
    HANDLE          ParametersKey;
    NTSTATUS        status;

    status = RegistryOpenServiceKey(KEY_READ, &ServiceKey);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = RegistryOpenSubKey(ServiceKey, "Parameters", KEY_READ, &ParametersKey);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RegistryQueryDwordValue(ParametersKey,
                                     "Revision",
                                     &Pdo->Revision);
    if (!NT_SUCCESS(status))
        goto fail3;

    RegistryCloseKey(ParametersKey);
    RegistryCloseKey(ServiceKey);

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

    RegistryCloseKey(ParametersKey);

fail2:
    Error("fail2\n");

    RegistryCloseKey(ServiceKey);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

static FORCEINLINE ULONG
__PdoGetRevision(
    IN  PXEN_PDO    Pdo
    )
{
    return Pdo->Revision;
}

static FORCEINLINE PDEVICE_OBJECT
__PdoGetDeviceObject(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_DX         Dx = Pdo->Dx;

    return  Dx->DeviceObject;
}
    
PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXEN_PDO    Pdo
    )
{
    return __PdoGetDeviceObject(Pdo);
}

static FORCEINLINE VOID
__PdoLink(
    IN  PXEN_PDO    Pdo,
    IN  PXEN_FDO    Fdo
    )
{
    Pdo->Fdo = Fdo;
    FdoAddPhysicalDeviceObject(Fdo, Pdo);
}

static FORCEINLINE VOID
__PdoUnlink(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_FDO        Fdo = Pdo->Fdo;

    ASSERT(Fdo != NULL);

    FdoRemovePhysicalDeviceObject(Fdo, Pdo);

    Pdo->Fdo = NULL;
}

static FORCEINLINE PXEN_FDO
__PdoGetFdo(
    IN  PXEN_PDO    Pdo
    )
{
    return Pdo->Fdo;
}

static FORCEINLINE PCHAR
__PdoGetVendorName(
    IN  PXEN_PDO    Pdo
    )
{
    return FdoGetVendorName(__PdoGetFdo(Pdo));
}

static FORCEINLINE PXEN_HYPERCALL_INTERFACE
__PdoGetHypercallInterface(
    IN  PXEN_PDO    Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    return FdoGetHypercallInterface(__PdoGetFdo(Pdo));
}

PXEN_HYPERCALL_INTERFACE
PdoGetHypercallInterface(
    IN  PXEN_PDO    Pdo
    )
{
    return __PdoGetHypercallInterface(Pdo);
}

PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXEN_PDO            Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    )
{
    return FdoGetDmaAdapter(__PdoGetFdo(Pdo),
                            DeviceDescriptor,
                            NumberOfMapRegisters);
}

BOOLEAN
PdoTranslateAddress(
    IN      PXEN_PDO            Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    )
{
    return FdoTranslateAddress(__PdoGetFdo(Pdo),
                               BusAddress,
                               Length,
                               AddressSpace,
                               TranslatedAddress);
}

ULONG
PdoSetData(
    IN  PXEN_PDO    Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    )
{
    return FdoSetData(__PdoGetFdo(Pdo),
                      DataType,
                      Buffer,
                      Offset,
                      Length);
}

ULONG
PdoGetData(
    IN  PXEN_PDO    Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    )
{
    return FdoGetData(__PdoGetFdo(Pdo),
                      DataType,
                      Buffer,
                      Offset,
                      Length);
}

static FORCEINLINE VOID
__PdoD3ToD0(
    IN  PXEN_PDO    Pdo
    )
{
    POWER_STATE     PowerState;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD3);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD0;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    Trace("<====\n");
}

static FORCEINLINE VOID
__PdoD0ToD3(
    IN  PXEN_PDO    Pdo
    )
{
    POWER_STATE     PowerState;

    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3U(__PdoGetDevicePowerState(Pdo), ==, PowerDeviceD0);

    PowerState.DeviceState = PowerDeviceD3;
    PoSetPowerState(__PdoGetDeviceObject(Pdo),
                    DevicePowerState,
                    PowerState);

    __PdoSetDevicePowerState(Pdo, PowerDeviceD3);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE NTSTATUS
PdoD3ToD0(
    IN  PXEN_PDO Pdo
    )
{
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __PdoD3ToD0(Pdo);
    KeLowerIrql(Irql);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
PdoD0ToD3(
    IN  PXEN_PDO Pdo
    )
{
    KIRQL           Irql;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);
    __PdoD0ToD3(Pdo);
    KeLowerIrql(Irql);
}

static DECLSPEC_NOINLINE VOID
PdoS4ToS3(
    IN  PXEN_PDO Pdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemHibernate);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE VOID
PdoS3ToS4(
    IN  PXEN_PDO Pdo
    )
{
    Trace("====>\n");

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);
    ASSERT3U(__PdoGetSystemPowerState(Pdo), ==, PowerSystemSleeping3);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);

    Trace("<====\n");
}

static DECLSPEC_NOINLINE VOID
PdoParseResources(
    IN  PXEN_PDO                Pdo,
    IN  PCM_RESOURCE_LIST       RawResourceList,
    IN  PCM_RESOURCE_LIST       TranslatedResourceList
    )
{
    PCM_PARTIAL_RESOURCE_LIST   RawPartialList;
    PCM_PARTIAL_RESOURCE_LIST   TranslatedPartialList;
    ULONG                       Index;

    UNREFERENCED_PARAMETER(Pdo);

    ASSERT3U(RawResourceList->Count, ==, 1);
    RawPartialList = &RawResourceList->List[0].PartialResourceList;

    ASSERT3U(RawPartialList->Version, ==, 1);
    ASSERT3U(RawPartialList->Revision, ==, 1);

    ASSERT3U(TranslatedResourceList->Count, ==, 1);
    TranslatedPartialList = &TranslatedResourceList->List[0].PartialResourceList;

    ASSERT3U(TranslatedPartialList->Version, ==, 1);
    ASSERT3U(TranslatedPartialList->Revision, ==, 1);

    for (Index = 0; Index < TranslatedPartialList->Count; Index++) {
        PCM_PARTIAL_RESOURCE_DESCRIPTOR RawPartialDescriptor;
        PCM_PARTIAL_RESOURCE_DESCRIPTOR TranslatedPartialDescriptor;

        RawPartialDescriptor = &RawPartialList->PartialDescriptors[Index];
        TranslatedPartialDescriptor = &TranslatedPartialList->PartialDescriptors[Index];

        Info("[%d] %02x:%s\n",
             Index,
             TranslatedPartialDescriptor->Type,
             PartialResourceDescriptorTypeName(TranslatedPartialDescriptor->Type));

        switch (TranslatedPartialDescriptor->Type) {
        case CmResourceTypeMemory:
            Info("RAW: SharedDisposition=%02x Flags=%04x Start = %08x.%08x Length = %08x\n",
                 RawPartialDescriptor->ShareDisposition,
                 RawPartialDescriptor->Flags,
                 RawPartialDescriptor->u.Memory.Start.HighPart,
                 RawPartialDescriptor->u.Memory.Start.LowPart,
                 RawPartialDescriptor->u.Memory.Length);

            Info("TRANSLATED: SharedDisposition=%02x Flags=%04x Start = %08x.%08x Length = %08x\n",
                 TranslatedPartialDescriptor->ShareDisposition,
                 TranslatedPartialDescriptor->Flags,
                 TranslatedPartialDescriptor->u.Memory.Start.HighPart,
                 TranslatedPartialDescriptor->u.Memory.Start.LowPart,
                 TranslatedPartialDescriptor->u.Memory.Length);
            break;

        case CmResourceTypeInterrupt:
            Info("RAW: SharedDisposition=%02x Flags=%04x Level = %08x Vector = %08x Affinity = %p\n",
                 RawPartialDescriptor->ShareDisposition,
                 RawPartialDescriptor->Flags,
                 RawPartialDescriptor->u.Interrupt.Level,
                 RawPartialDescriptor->u.Interrupt.Vector,
                 (PVOID)RawPartialDescriptor->u.Interrupt.Affinity);

            Info("TRANSLATED: SharedDisposition=%02x Flags=%04x Level = %08x Vector = %08x Affinity = %p\n",
                 TranslatedPartialDescriptor->ShareDisposition,
                 TranslatedPartialDescriptor->Flags,
                 TranslatedPartialDescriptor->u.Interrupt.Level,
                 TranslatedPartialDescriptor->u.Interrupt.Vector,
                 (PVOID)TranslatedPartialDescriptor->u.Interrupt.Affinity);
            break;

        default:
            break;
        }
    }

    Trace("<====\n");
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStartDevice(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    PdoParseResources(Pdo,
                      StackLocation->Parameters.StartDevice.AllocatedResources,
                      StackLocation->Parameters.StartDevice.AllocatedResourcesTranslated);

    __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);

    PdoS4ToS3(Pdo);
    
    __PdoSetSystemPowerState(Pdo, PowerSystemWorking);

    PdoD3ToD0(Pdo);

    __PdoSetDevicePnpState(Pdo, Started);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryStopDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, StopPending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelStopDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoRestoreDevicePnpState(Pdo, StopPending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoStopDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    PdoD0ToD3(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    PdoS3ToS4(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

    __PdoSetDevicePnpState(Pdo, Stopped);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryRemoveDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoCancelRemoveDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoRestoreDevicePnpState(Pdo, RemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSurpriseRemoval(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    __PdoSetDevicePnpState(Pdo, SurpriseRemovePending);
    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoRemoveDevice(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    PXEN_FDO        Fdo = __PdoGetFdo(Pdo);
    NTSTATUS        status;

    if (__PdoGetDevicePowerState(Pdo) != PowerDeviceD0)
        goto done;

    PdoD0ToD3(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);

    PdoS3ToS4(Pdo);

    __PdoSetSystemPowerState(Pdo, PowerSystemShutdown);

done:
    FdoAcquireMutex(Fdo);

    if (__PdoIsMissing(Pdo) ||
        __PdoGetDevicePnpState(Pdo) == SurpriseRemovePending)
        __PdoSetDevicePnpState(Pdo, Deleted);
    else
        __PdoSetDevicePnpState(Pdo, Enumerated);

    if (__PdoIsMissing(Pdo)) {
        if (__PdoGetDevicePnpState(Pdo) == Deleted)
            PdoDestroy(Pdo);
        else
            IoInvalidateDeviceRelations(FdoGetPhysicalDeviceObject(Fdo), 
                                        BusRelations);
    }

    FdoReleaseMutex(Fdo);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceRelations(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PDEVICE_RELATIONS   Relations;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    status = Irp->IoStatus.Status;

    if (StackLocation->Parameters.QueryDeviceRelations.Type != TargetDeviceRelation)
        goto done;

    Relations = ExAllocatePoolWithTag(PagedPool, sizeof (DEVICE_RELATIONS), 'SUB');

    status = STATUS_NO_MEMORY;
    if (Relations == NULL)
        goto done;

    RtlZeroMemory(Relations, sizeof (DEVICE_RELATIONS));

    Relations->Count = 1;
    ObReferenceObject(__PdoGetDeviceObject(Pdo));
    Relations->Objects[0] = __PdoGetDeviceObject(Pdo);

    Irp->IoStatus.Information = (ULONG_PTR)Relations;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoDelegateIrp(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    return FdoDelegateIrp(__PdoGetFdo(Pdo), Irp);
}

static NTSTATUS
PdoQueryBusInterface(
    IN  PXEN_PDO            Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    USHORT                  Size;
    USHORT                  Version;
    PBUS_INTERFACE_STANDARD BusInterface;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Size = StackLocation->Parameters.QueryInterface.Size;
    Version = StackLocation->Parameters.QueryInterface.Version;
    BusInterface = (PBUS_INTERFACE_STANDARD)StackLocation->Parameters.QueryInterface.Interface;

    if (StackLocation->Parameters.QueryInterface.Version != 1)
        goto done;

    status = STATUS_BUFFER_TOO_SMALL;        
    if (StackLocation->Parameters.QueryInterface.Size < sizeof (BUS_INTERFACE_STANDARD))
        goto done;

    *BusInterface = Pdo->BusInterface;
    BusInterface->InterfaceReference(BusInterface->Context);

    Irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;

done:
    return status;
}

static NTSTATUS
PdoQueryHypercallInterface(
    IN  PXEN_PDO            Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    USHORT                  Size;
    USHORT                  Version;
    PINTERFACE              Interface;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;        

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Size = StackLocation->Parameters.QueryInterface.Size;
    Version = StackLocation->Parameters.QueryInterface.Version;
    Interface = StackLocation->Parameters.QueryInterface.Interface;

    if (StackLocation->Parameters.QueryInterface.Version != HYPERCALL_INTERFACE_VERSION)
        goto done;

    status = STATUS_BUFFER_TOO_SMALL;        
    if (StackLocation->Parameters.QueryInterface.Size < sizeof (INTERFACE))
        goto done;

    Interface->Size = sizeof (INTERFACE);
    Interface->Version = HYPERCALL_INTERFACE_VERSION;
    Interface->Context = __PdoGetHypercallInterface(Pdo);
    Interface->InterfaceReference = NULL;
    Interface->InterfaceDereference = NULL;

    Irp->IoStatus.Information = 0;
    status = STATUS_SUCCESS;

done:
    return status;
}

struct _INTERFACE_ENTRY {
    const GUID  *Guid;
    const CHAR  *Name;
    NTSTATUS    (*Handler)(PXEN_PDO, PIRP);
};

#define DEFINE_HANDLER(_Guid, _Function)    \
        { &GUID_ ## _Guid, #_Guid, (_Function) }

struct _INTERFACE_ENTRY PdoInterfaceTable[] = {
    DEFINE_HANDLER(BUS_INTERFACE_STANDARD, PdoQueryBusInterface),
    DEFINE_HANDLER(HYPERCALL_INTERFACE, PdoQueryHypercallInterface),
    { NULL, NULL, NULL }
};

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryInterface(
    IN  PXEN_PDO            Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    const GUID              *InterfaceType;
    struct _INTERFACE_ENTRY *Entry;
    NTSTATUS                status;

    status = Irp->IoStatus.Status;

    if (status != STATUS_NOT_SUPPORTED)
        goto done;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    InterfaceType = StackLocation->Parameters.QueryInterface.InterfaceType;

    for (Entry = PdoInterfaceTable; Entry->Guid != NULL; Entry++) {
        if (IsEqualGUID(InterfaceType, Entry->Guid)) {
            Trace("%s\n", Entry->Name);
            status = Entry->Handler(Pdo, Irp);
            goto done;
        }
    }

    status = __PdoDelegateIrp(Pdo, Irp);

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryCapabilities(
    IN  PXEN_PDO            Pdo,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    PDEVICE_CAPABILITIES    Capabilities;
    SYSTEM_POWER_STATE      SystemPowerState;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Capabilities = StackLocation->Parameters.DeviceCapabilities.Capabilities;

    status = STATUS_INVALID_PARAMETER;
    if (Capabilities->Version != 1)
        goto done;

    Capabilities->DeviceD1 = 0;
    Capabilities->DeviceD2 = 0;
    Capabilities->LockSupported = 0;
    Capabilities->EjectSupported = 0;
    Capabilities->Removable = 1;
    Capabilities->DockDevice = 0;
    Capabilities->UniqueID = 1;
    Capabilities->SilentInstall = 1;
    Capabilities->RawDeviceOK = 0;
    Capabilities->SurpriseRemovalOK = 1;
    Capabilities->HardwareDisabled = 0;
    Capabilities->NoDisplayInUI = 0;

    Capabilities->Address = 0xffffffff;
    Capabilities->UINumber = 0xffffffff;

    for (SystemPowerState = 0; SystemPowerState < PowerSystemMaximum; SystemPowerState++) {
        switch (SystemPowerState) {
        case PowerSystemUnspecified:
        case PowerSystemSleeping1:
        case PowerSystemSleeping2:
            break;

        case PowerSystemWorking:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD0;
            break;

        default:
            Capabilities->DeviceState[SystemPowerState] = PowerDeviceD3;
            break;
        }
    }

    Capabilities->SystemWake = PowerSystemUnspecified;
    Capabilities->DeviceWake = PowerDeviceUnspecified;
    Capabilities->D1Latency = 0;
    Capabilities->D2Latency = 0;
    Capabilities->D3Latency = 0;

    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryResourceRequirements(
    IN  PXEN_PDO                    Pdo,
    IN  PIRP                        Irp
    )
{
    IO_RESOURCE_DESCRIPTOR          Memory;
    IO_RESOURCE_DESCRIPTOR          Interrupt;
    ULONG                           Size;
    PIO_RESOURCE_REQUIREMENTS_LIST  Requirements;
    PIO_RESOURCE_LIST               List;
    NTSTATUS                        status;

    UNREFERENCED_PARAMETER(Pdo);

    RtlZeroMemory(&Memory, sizeof (IO_RESOURCE_DESCRIPTOR));
    Memory.Type = CmResourceTypeMemory;
    Memory.ShareDisposition = CmResourceShareDeviceExclusive;
    Memory.Flags = CM_RESOURCE_MEMORY_READ_WRITE |
                   CM_RESOURCE_MEMORY_PREFETCHABLE |
                   CM_RESOURCE_MEMORY_CACHEABLE;

    Memory.u.Memory.Length = PAGE_SIZE;
    Memory.u.Memory.Alignment = PAGE_SIZE;
    Memory.u.Memory.MinimumAddress.QuadPart = 0;
    Memory.u.Memory.MaximumAddress.QuadPart = -1;

    RtlZeroMemory(&Interrupt, sizeof (IO_RESOURCE_DESCRIPTOR));
    Interrupt.Type = CmResourceTypeInterrupt;
    Interrupt.ShareDisposition = CmResourceShareDeviceExclusive;
    Interrupt.Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;

    Interrupt.u.Interrupt.MinimumVector = (ULONG)0;
    Interrupt.u.Interrupt.MaximumVector = (ULONG)-1;
    Interrupt.u.Interrupt.AffinityPolicy = IrqPolicyOneCloseProcessor;
    Interrupt.u.Interrupt.PriorityPolicy = IrqPriorityUndefined;

    Size = sizeof (IO_RESOURCE_DESCRIPTOR) * 2;
    Size += FIELD_OFFSET(IO_RESOURCE_LIST, Descriptors);
    Size += FIELD_OFFSET(IO_RESOURCE_REQUIREMENTS_LIST, List);

    Requirements = ExAllocatePoolWithTag(PagedPool, Size, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Requirements == NULL)
        goto fail1;

    RtlZeroMemory(Requirements, Size);

    Requirements->ListSize = Size;
    Requirements->InterfaceType = Internal;
    Requirements->BusNumber = 0;
    Requirements->SlotNumber = 0;
    Requirements->AlternativeLists = 1;

    List = &Requirements->List[0];
    List->Version = 1;
    List->Revision = 1;
    List->Count = 2;
    List->Descriptors[0] = Memory;
    List->Descriptors[1] = Interrupt;

    Irp->IoStatus.Information = (ULONG_PTR)Requirements;

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;

fail1:
    Error("fail1 (%08x)\n", status);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

#define MAXTEXTLEN  (128 * sizeof (WCHAR))

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryDeviceText(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Text;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription:
        Trace("DeviceTextDescription\n");
        break;

    case DeviceTextLocationInformation:
        Trace("DeviceTextLocationInformation\n");
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, MAXTEXTLEN, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, MAXTEXTLEN);

    Text.Buffer = Buffer;
    Text.MaximumLength = MAXTEXTLEN;
    Text.Length = 0;

    switch (StackLocation->Parameters.QueryDeviceText.DeviceTextType) {
    case DeviceTextDescription: {
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"%hs",
                                    FdoGetName(__PdoGetFdo(Pdo)));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;
    }
    case DeviceTextLocationInformation:
        status = RtlStringCbPrintfW(Buffer,
                                    MAXTEXTLEN,
                                    L"_");
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Text.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Text.Buffer);

    Trace("%wZ\n", &Text);

    Irp->IoStatus.Information = (ULONG_PTR)Text.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoReadConfig(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoWriteConfig(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    UNREFERENCED_PARAMETER(Pdo);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_NOT_SUPPORTED;
}

#define MAX_DEVICE_ID_LEN   200

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryId(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    PWCHAR              Buffer;
    UNICODE_STRING      Id;
    ULONG               Type;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Trace("BusQueryInstanceID\n");
        break;

    case BusQueryDeviceID:
        Trace("BusQueryDeviceID\n");
        break;

    case BusQueryHardwareIDs:
        Trace("BusQueryHardwareIDs\n");
        break;

    case BusQueryCompatibleIDs:
        Trace("BusQueryCompatibleIDs\n");
        break;

    default:
        Irp->IoStatus.Information = 0;
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, MAX_DEVICE_ID_LEN, 'SUB');

    status = STATUS_NO_MEMORY;
    if (Buffer == NULL)
        goto done;

    RtlZeroMemory(Buffer, MAX_DEVICE_ID_LEN);

    Id.Buffer = Buffer;
    Id.MaximumLength = MAX_DEVICE_ID_LEN;
    Id.Length = 0;

    switch (StackLocation->Parameters.QueryId.IdType) {
    case BusQueryInstanceID:
        Type = REG_SZ;

        RtlAppendUnicodeToString(&Id, L"_");
        break;

    case BusQueryDeviceID:
        Type = REG_SZ;

        status = RtlStringCbPrintfW(Buffer,
                                    MAX_DEVICE_ID_LEN,
                                    L"XEN\\VEN_%hs&REV_%08X",
                                    __PdoGetVendorName(Pdo),
                                    __PdoGetRevision(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);

        break;

    case BusQueryHardwareIDs:
    case BusQueryCompatibleIDs: {
        ULONG   Length;

        Type = REG_MULTI_SZ;

        Length = MAX_DEVICE_ID_LEN;
        status = RtlStringCbPrintfW(Buffer,
                                    Length,
                                    L"XEN\\VEN_%hs&REV_%08X",
                                    __PdoGetVendorName(Pdo),
                                    __PdoGetRevision(Pdo));
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);
        Buffer++;

        Length = MAX_DEVICE_ID_LEN - (ULONG)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer); 
        status = RtlStringCbPrintfW(Buffer,
                                    Length,
                                    L"PLATFORM");
        ASSERT(NT_SUCCESS(status));

        Buffer += wcslen(Buffer);
        Buffer++;

        break;
    }
    default:
        Type = REG_NONE;

        ASSERT(FALSE);
        break;
    }

    Id.Length = (USHORT)((ULONG_PTR)Buffer - (ULONG_PTR)Id.Buffer);
    Buffer = Id.Buffer;

    ASSERT3U(KeGetCurrentIrql(), ==, PASSIVE_LEVEL);

    switch (Type) {
    case REG_SZ:
        Trace("- %ws\n", Buffer);
        break;

    case REG_MULTI_SZ:
        do {
            Trace("- %ws\n", Buffer);
            Buffer += wcslen(Buffer);
            Buffer++;
        } while (*Buffer != L'\0');
        break;

    default:
        ASSERT(FALSE);
        break;
    }

    Irp->IoStatus.Information = (ULONG_PTR)Id.Buffer;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryBusInformation(
    IN  PXEN_PDO            Pdo,
    IN  PIRP                Irp
    )
{
    PPNP_BUS_INFORMATION    Info;
    NTSTATUS                status;

    UNREFERENCED_PARAMETER(Pdo);

    Info = ExAllocatePoolWithTag(PagedPool, sizeof (PNP_BUS_INFORMATION), 'SUB');

    status = STATUS_NO_MEMORY;
    if (Info == NULL)
        goto done;

    RtlZeroMemory(Info, sizeof (PNP_BUS_INFORMATION));

    Info->BusTypeGuid = GUID_BUS_TYPE_INTERNAL;
    Info->LegacyBusType = Internal;
    Info->BusNumber = 0;

    Irp->IoStatus.Information = (ULONG_PTR)Info;
    status = STATUS_SUCCESS;

done:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDeviceUsageNotification(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    status = __PdoDelegateIrp(Pdo, Irp);

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPnp(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    Trace("====> (%02x:%s)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction));

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        status = PdoStartDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        status = PdoQueryStopDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        status = PdoCancelStopDevice(Pdo, Irp);
        break;

    case IRP_MN_STOP_DEVICE:
        status = PdoStopDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        status = PdoQueryRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        status = PdoCancelRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        status = PdoSurpriseRemoval(Pdo, Irp);
        break;

    case IRP_MN_REMOVE_DEVICE:
        status = PdoRemoveDevice(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_RELATIONS:
        status = PdoQueryDeviceRelations(Pdo, Irp);
        break;

    case IRP_MN_QUERY_INTERFACE:
        status = PdoQueryInterface(Pdo, Irp);
        break;

    case IRP_MN_QUERY_CAPABILITIES:
        status = PdoQueryCapabilities(Pdo, Irp);
        break;

    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
        status = PdoQueryResourceRequirements(Pdo, Irp);
        break;

    case IRP_MN_QUERY_DEVICE_TEXT:
        status = PdoQueryDeviceText(Pdo, Irp);
        break;

    case IRP_MN_READ_CONFIG:
        status = PdoReadConfig(Pdo, Irp);
        break;

    case IRP_MN_WRITE_CONFIG:
        status = PdoWriteConfig(Pdo, Irp);
        break;

    case IRP_MN_QUERY_ID:
        status = PdoQueryId(Pdo, Irp);
        break;

    case IRP_MN_QUERY_BUS_INFORMATION:
        status = PdoQueryBusInformation(Pdo, Irp);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        status = PdoDeviceUsageNotification(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    Trace("<==== (%02x:%s)(%08x)\n",
          MinorFunction, 
          PnpMinorFunctionName(MinorFunction),
          status);

    return status;
}

static FORCEINLINE NTSTATUS
__PdoSetDevicePower(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    DEVICE_POWER_STATE  DeviceState;
    POWER_ACTION        PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    DeviceState = StackLocation->Parameters.Power.State.DeviceState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetDevicePowerState(Pdo) > DeviceState) {
        Trace("POWERING UP: %s -> %s\n",
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD0);
        PdoD3ToD0(Pdo);
    } else if (__PdoGetDevicePowerState(Pdo) < DeviceState) {
        Trace("POWERING DOWN: %s -> %s\n",
              PowerDeviceStateName(__PdoGetDevicePowerState(Pdo)),
              PowerDeviceStateName(DeviceState));

        ASSERT3U(DeviceState, ==, PowerDeviceD3);
        PdoD0ToD3(Pdo);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          PowerDeviceStateName(DeviceState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoDevicePower(
    IN  PXEN_THREAD Self,
    IN  PVOID       Context
    )
{
    PXEN_PDO        Pdo = Context;
    PKEVENT         Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

        if (Pdo->DevicePowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->DevicePowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->DevicePowerIrp = NULL;
        KeMemoryBarrier();

        (VOID) __PdoSetDevicePower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__PdoSetSystemPower(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    SYSTEM_POWER_STATE  SystemState;
    POWER_ACTION        PowerAction;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    SystemState = StackLocation->Parameters.Power.State.SystemState;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    Trace("====> (%s:%s)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    ASSERT3U(PowerAction, <, PowerActionShutdown);

    if (__PdoGetSystemPowerState(Pdo) > SystemState) {
        if (SystemState < PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) >= PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemHibernate);
            PdoS4ToS3(Pdo);
        }

        Trace("POWERING UP: %s -> %s\n",
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));

    } else if (__PdoGetSystemPowerState(Pdo) < SystemState) {
        Trace("POWERING DOWN: %s -> %s\n",
              PowerSystemStateName(__PdoGetSystemPowerState(Pdo)),
              PowerSystemStateName(SystemState));

        if (SystemState >= PowerSystemHibernate &&
            __PdoGetSystemPowerState(Pdo) < PowerSystemHibernate) {
            __PdoSetSystemPowerState(Pdo, PowerSystemSleeping3);
            PdoS3ToS4(Pdo);
        }
    }

    __PdoSetSystemPowerState(Pdo, SystemState);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    Trace("<==== (%s:%s)\n",
          PowerSystemStateName(SystemState), 
          PowerActionName(PowerAction));

    return STATUS_SUCCESS;
}

static NTSTATUS
PdoSystemPower(
    IN  PXEN_THREAD Self,
    IN  PVOID       Context
    )
{
    PXEN_PDO        Pdo = Context;
    PKEVENT         Event;

    Event = ThreadGetEvent(Self);

    for (;;) {
        PIRP    Irp;

        if (Pdo->SystemPowerIrp == NULL) {
            (VOID) KeWaitForSingleObject(Event,
                                         Executive,
                                         KernelMode,
                                         FALSE,
                                         NULL);
            KeClearEvent(Event);
        }

        if (ThreadIsAlerted(Self))
            break;

        Irp = Pdo->SystemPowerIrp;

        if (Irp == NULL)
            continue;

        Pdo->SystemPowerIrp = NULL;
        KeMemoryBarrier();

        (VOID) __PdoSetSystemPower(Pdo, Irp);
    }

    return STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoSetPower(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    POWER_STATE_TYPE    PowerType;
    POWER_ACTION        PowerAction;
    NTSTATUS            status;
    
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    PowerType = StackLocation->Parameters.Power.Type;
    PowerAction = StackLocation->Parameters.Power.ShutdownType;

    if (PowerAction >= PowerActionShutdown) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        goto done;
    }

    switch (PowerType) {
    case DevicePowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->DevicePowerIrp, ==, NULL);
        Pdo->DevicePowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->DevicePowerThread);

        status = STATUS_PENDING;
        break;

    case SystemPowerState:
        IoMarkIrpPending(Irp);

        ASSERT3P(Pdo->SystemPowerIrp, ==, NULL);
        Pdo->SystemPowerIrp = Irp;
        KeMemoryBarrier();

        ThreadWake(Pdo->SystemPowerThread);

        status = STATUS_PENDING;
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

done:
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoQueryPower(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = STATUS_SUCCESS;

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchPower(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    UCHAR               MinorFunction;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    MinorFunction = StackLocation->MinorFunction;

    switch (StackLocation->MinorFunction) {
    case IRP_MN_SET_POWER:
        status = PdoSetPower(Pdo, Irp);
        break;

    case IRP_MN_QUERY_POWER:
        status = PdoQueryPower(Pdo, Irp);
        break;

    default:
        status = Irp->IoStatus.Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        break;
    }

    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
PdoDispatchDefault(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    )
{
    NTSTATUS        status;

    UNREFERENCED_PARAMETER(Pdo);

    status = Irp->IoStatus.Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
PdoDispatch(
    IN  PXEN_PDO        Pdo,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    NTSTATUS            status;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (StackLocation->MajorFunction) {
    case IRP_MJ_PNP:
        status = PdoDispatchPnp(Pdo, Irp);
        break;

    case IRP_MJ_POWER:
        status = PdoDispatchPower(Pdo, Irp);
        break;

    default:
        status = PdoDispatchDefault(Pdo, Irp);
        break;
    }

    return status;
}

VOID
PdoResume(
    IN  PXEN_PDO    Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);
}

VOID
PdoSuspend(
    IN  PXEN_PDO    Pdo
    )
{
    UNREFERENCED_PARAMETER(Pdo);
}

NTSTATUS
PdoCreate(
    IN  PXEN_FDO    Fdo
    )
{
    PDEVICE_OBJECT  PhysicalDeviceObject;
    PXEN_DX         Dx;
    PXEN_PDO        Pdo;
    NTSTATUS        status;

#pragma prefast(suppress:28197) // Possibly leaking memory 'PhysicalDeviceObject'
    status = IoCreateDevice(DriverGetDriverObject(),
                            sizeof(XEN_DX),
                            NULL,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN | FILE_AUTOGENERATED_DEVICE_NAME,
                            FALSE,
                            &PhysicalDeviceObject);
    if (!NT_SUCCESS(status))
        goto fail1;

    Dx = (PXEN_DX)PhysicalDeviceObject->DeviceExtension;
    RtlZeroMemory(Dx, sizeof (XEN_DX));

    Dx->Type = PHYSICAL_DEVICE_OBJECT;
    Dx->DeviceObject = PhysicalDeviceObject;
    Dx->DevicePnpState = Present;

    Dx->SystemPowerState = PowerSystemShutdown;
    Dx->DevicePowerState = PowerDeviceD3;

    Pdo = __PdoAllocate(sizeof (XEN_PDO));

    status = STATUS_NO_MEMORY;
    if (Pdo == NULL)
        goto fail2;

    Pdo->Dx = Dx;

    status = BusInitialize(Pdo, &Pdo->BusInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = ThreadCreate(PdoSystemPower, Pdo, &Pdo->SystemPowerThread);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ThreadCreate(PdoDevicePower, Pdo, &Pdo->DevicePowerThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    Info("%p\n", PhysicalDeviceObject);

    Dx->Pdo = Pdo;
    PhysicalDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    __PdoLink(Pdo, Fdo);

    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");

    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

fail4:
    Error("fail4\n");

    BusTeardown(&Pdo->BusInterface);

fail3:
    Error("fail3\n");

    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XEN_PDO)));
    __PdoFree(Pdo);

fail2:
    Error("fail2\n");

    IoDeleteDevice(PhysicalDeviceObject);

fail1:
    Error("fail1 (%08x)\n", status);

    return status;
}

VOID
PdoDestroy(
    IN  PXEN_PDO    Pdo
    )
{
    PXEN_DX         Dx = Pdo->Dx;
    PDEVICE_OBJECT  PhysicalDeviceObject = Dx->DeviceObject;

    ASSERT3U(__PdoGetDevicePnpState(Pdo), ==, Deleted);

    ASSERT(__PdoIsMissing(Pdo));
    Pdo->Missing = FALSE;

    __PdoUnlink(Pdo);

    Info("%p (%s)\n",
         PhysicalDeviceObject,
         Pdo->Reason);
    Pdo->Reason = NULL;

    Dx->Pdo = NULL;

    ThreadAlert(Pdo->DevicePowerThread);
    ThreadJoin(Pdo->DevicePowerThread);
    Pdo->DevicePowerThread = NULL;
    
    ThreadAlert(Pdo->SystemPowerThread);
    ThreadJoin(Pdo->SystemPowerThread);
    Pdo->SystemPowerThread = NULL;

    BusTeardown(&Pdo->BusInterface);

    Pdo->Dx = NULL;

    ASSERT(IsZeroMemory(Pdo, sizeof (XEN_PDO)));
    __PdoFree(Pdo);

    IoDeleteDevice(PhysicalDeviceObject);
}
