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

#ifndef _XEN_FDO_H
#define _XEN_FDO_H

#include <ntddk.h>

#include "driver.h"
#include "types.h"

typedef enum _XEN_RESOURCE_TYPE {
    MEMORY_RESOURCE = 0,
    INTERRUPT_RESOURCE,
    RESOURCE_COUNT
} XEN_RESOURCE_TYPE, *PXEN_RESOURCE_TYPE;

typedef struct _XEN_RESOURCE {
    CM_PARTIAL_RESOURCE_DESCRIPTOR Raw;
    CM_PARTIAL_RESOURCE_DESCRIPTOR Translated;
} XEN_RESOURCE, *PXEN_RESOURCE;

extern NTSTATUS
FdoCreate(
    IN  PDEVICE_OBJECT  PhysicalDeviceObject,
    IN  BOOLEAN         Active
    );

extern VOID
FdoDestroy(
    IN  PXEN_FDO    Fdo
    );

extern NTSTATUS
FdoDelegateIrp(
    IN  PXEN_FDO    Fdo,
    IN  PIRP        Irp
    );

extern VOID
FdoAddPhysicalDeviceObject(
    IN  PXEN_FDO    Fdo,
    IN  PXEN_PDO    Pdo
    );

extern VOID
FdoRemovePhysicalDeviceObject(
    IN  PXEN_FDO    Fdo,
    IN  PXEN_PDO    Pdo
    );

extern VOID
FdoAcquireMutex(
    IN  PXEN_FDO    Fdo
    );

extern VOID
FdoReleaseMutex(
    IN  PXEN_FDO    Fdo
    );

extern PDEVICE_OBJECT
FdoGetPhysicalDeviceObject(
    IN  PXEN_FDO    Fdo
    );

extern BOOLEAN
FdoTranslateAddress(
    IN      PXEN_FDO            Fdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

extern PDMA_ADAPTER
FdoGetDmaAdapter(
    IN  PXEN_FDO            Fdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern ULONG
FdoSetData(
    IN  PXEN_FDO    Fdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern ULONG
FdoGetData(
    IN  PXEN_FDO    Fdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern PCHAR
FdoGetName(
    IN  PXEN_FDO    Fdo
    );

extern PCHAR
FdoGetVendorName(
    IN  PXEN_FDO    Fdo
    );

#include "hypercall.h"

extern PXEN_HYPERCALL_INTERFACE
FdoGetHypercallInterface(
    IN  PXEN_FDO    Fdo
    );

extern NTSTATUS
FdoDispatch(
    IN  PXEN_FDO    Fdo,
    IN  PIRP        Irp
    );

#endif  // _XEN_FDO_H
