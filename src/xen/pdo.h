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

#ifndef _XEN_PDO_H
#define _XEN_PDO_H

#include <ntddk.h>

#include "driver.h"
#include "device.h"

extern VOID
PdoSetDevicePnpState(
    IN  PXEN_PDO            Pdo,
    IN  DEVICE_PNP_STATE    State
    );

extern DEVICE_PNP_STATE
PdoGetDevicePnpState(
    IN  PXEN_PDO    Pdo
    );

extern BOOLEAN
PdoIsMissing(
    IN  PXEN_PDO    Pdo
    );

extern VOID
PdoSetMissing(
    IN  PXEN_PDO    Pdo,
    IN  const CHAR  *Reason
    );

extern PDEVICE_OBJECT
PdoGetDeviceObject(
    IN  PXEN_PDO    Pdo
    );

extern BOOLEAN
PdoTranslateAddress(
    IN      PXEN_PDO            Pdo,
    IN      PHYSICAL_ADDRESS    BusAddress,
    IN      ULONG               Length,
    IN OUT  PULONG              AddressSpace,
    OUT     PPHYSICAL_ADDRESS   TranslatedAddress
    );

PDMA_ADAPTER
PdoGetDmaAdapter(
    IN  PXEN_PDO            Pdo,
    IN  PDEVICE_DESCRIPTION DeviceDescriptor,
    OUT PULONG              NumberOfMapRegisters
    );

extern ULONG
PdoSetData(
    IN  PXEN_PDO    Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern ULONG
PdoGetData(
    IN  PXEN_PDO    Pdo,
    IN  ULONG       DataType,
    IN  PVOID       Buffer,
    IN  ULONG       Offset,
    IN  ULONG       Length
    );

extern NTSTATUS
PdoCreate(
    IN  PXEN_FDO    Fdo
    );

extern VOID
PdoResume(
    IN  PXEN_PDO    Pdo
    );

extern VOID
PdoSuspend(
    IN  PXEN_PDO    Pdo
    );

extern VOID
PdoDestroy(
    IN  PXEN_PDO    Pdo
    );

extern NTSTATUS
PdoDispatch(
    IN  PXEN_PDO    Pdo,
    IN  PIRP        Irp
    );

#endif  // _XEN_PDO_H
