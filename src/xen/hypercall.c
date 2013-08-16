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
#include <util.h>
#include <xen.h>

#include "hypercall.h"
#include "debug.h"
#include "assert.h"

#define MAXIMUM_HYPERCALL_PFN_COUNT 2

#pragma code_seg("hypercall")
__declspec(allocate("hypercall"))
static UCHAR        HypercallSection[(MAXIMUM_HYPERCALL_PFN_COUNT + 1) * PAGE_SIZE];

typedef UCHAR           HYPERCALL_GATE[32];
typedef HYPERCALL_GATE  *PHYPERCALL_GATE;

PHYPERCALL_GATE     HypercallBase;

typedef struct _XEN_HYPERCALL_CONTEXT {
    LONG            References;
    ULONG           Leaf;
} XEN_HYPERCALL_CONTEXT, *PXEN_HYPERCALL_CONTEXT;

#define HYPERCALL_TAG   'EPYH'

static FORCEINLINE PVOID
__HypercallAllocate(
    IN  ULONG   Length
    )
{
    return __AllocateNonPagedPoolWithTag(Length, HYPERCALL_TAG);
}

static FORCEINLINE VOID
__HypercallFree(
    IN  PVOID   Buffer
    )
{
    __FreePoolWithTag(Buffer, HYPERCALL_TAG);
}

extern uintptr_t __stdcall hypercall_2(uint32_t ord, uintptr_t arg1, uintptr_t arg2);
extern uintptr_t __stdcall hypercall_3(uint32_t ord, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3);

static DECLSPEC_NOINLINE ULONG_PTR
Hypercall(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Count,
    IN  ULONG                   Ordinal,
    ...
    )
{
    va_list                     Arguments;
    ULONG_PTR                   rc;

    UNREFERENCED_PARAMETER(Context);

    va_start(Arguments, Ordinal);
    switch (Count) {
    case 2: {
        ULONG_PTR   Argument1 = va_arg(Arguments, ULONG_PTR);
        ULONG_PTR   Argument2 = va_arg(Arguments, ULONG_PTR);

        rc = hypercall_2(Ordinal, Argument1, Argument2);
        break;
    }
    case 3: {
        ULONG_PTR   Argument1 = va_arg(Arguments, ULONG_PTR);
        ULONG_PTR   Argument2 = va_arg(Arguments, ULONG_PTR);
        ULONG_PTR   Argument3 = va_arg(Arguments, ULONG_PTR);

        rc = hypercall_3(Ordinal, Argument1, Argument2, Argument3);
        break;
    }
    default:
        rc = (ULONG_PTR)-ENOSYS;
    }
    va_end(Arguments);

    return rc;
}

static LONG_PTR
HypercallEventChannelOp(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument
    )
{
    return (LONG_PTR)Hypercall(Context, 2, __HYPERVISOR_event_channel_op, Command, Argument);
}

static LONG_PTR
HypercallHvmOp(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument
    )
{
    return (LONG_PTR)Hypercall(Context, 2, __HYPERVISOR_hvm_op, Command, Argument);
}

static LONG_PTR
HypercallMemoryOp(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument
    )
{
    return (LONG_PTR)Hypercall(Context, 2, __HYPERVISOR_memory_op, Command, Argument);
}

static LONG_PTR
HypercallSchedOp(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument
    )
{
    return (LONG_PTR)Hypercall(Context, 2, __HYPERVISOR_sched_op, Command, Argument);
}

static LONG_PTR
HypercallXenVersion(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument
    )
{
    return (LONG_PTR)Hypercall(Context, 2, __HYPERVISOR_xen_version, Command, Argument);
}

static LONG_PTR
HypercallGrantTableOp(
    IN  PXEN_HYPERCALL_CONTEXT  Context,
    IN  ULONG                   Command,
    IN  PVOID                   Argument,
    IN  ULONG                   Count
    )
{
    return (LONG_PTR)Hypercall(Context, 3, __HYPERVISOR_grant_table_op, Command, Argument, Count);
}

static VOID
HypercallAcquire(
    IN  PXEN_HYPERCALL_CONTEXT  Context
    )
{
    InterlockedIncrement(&Context->References);
}

static VOID
HypercallRelease(
    IN  PXEN_HYPERCALL_CONTEXT  Context
    )
{
    ASSERT(Context->References != 0);
    InterlockedDecrement(&Context->References);
}

#define HYPERCALL_OPERATION(_Type, _Name, _Arguments) \
        Hypercall ## _Name,

static XEN_HYPERCALL_OPERATIONS Operations = {
    DEFINE_HYPERCALL_OPERATIONS
};

#undef HYPERCALL_OPERATION

#define XEN_BASE_LEAF   0x40000000
#define XEN_SIGNATURE   "XenVMMXenVMM"

NTSTATUS
HypercallInitialize(
    OUT PXEN_HYPERCALL_INTERFACE    Interface
    )
{
    PXEN_HYPERCALL_CONTEXT          Context;
    ULONG                           EAX = 'DEAD';
    ULONG                           EBX = 'DEAD';
    ULONG                           ECX = 'DEAD';
    ULONG                           EDX = 'DEAD';
    PFN_NUMBER                      Pfn[MAXIMUM_HYPERCALL_PFN_COUNT];
    ULONG                           Index;
    ULONG                           Count;
    ULONG                           Msr;
    NTSTATUS                        status;

    Trace("====>\n");

    Context = __HypercallAllocate(sizeof (XEN_HYPERCALL_CONTEXT));

    status = STATUS_NO_MEMORY;
    if (Context == NULL)
        goto fail1;

    Context->Leaf = XEN_BASE_LEAF;

    status = STATUS_UNSUCCESSFUL;
    for (;;) {
        CHAR    Signature[13] = {0};

        __CpuId(Context->Leaf, &EAX, &EBX, &ECX, &EDX);
        *((PULONG)(Signature + 0)) = EBX;
        *((PULONG)(Signature + 4)) = ECX;
        *((PULONG)(Signature + 8)) = EDX;

        if (strcmp(Signature, XEN_SIGNATURE) == 0 &&
            EAX >= XEN_BASE_LEAF + 2)
            break;
            
        Context->Leaf += 0x100;
        
        if (Context->Leaf > XEN_BASE_LEAF + 0x100)
            goto fail2;
    }

    if ((ULONG_PTR)HypercallSection & (PAGE_SIZE - 1))
        HypercallBase = (PVOID)(((ULONG_PTR)HypercallSection + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    else
        HypercallBase = (PVOID)HypercallSection;

    ASSERT3U(((ULONG_PTR)HypercallBase & (PAGE_SIZE - 1)), ==, 0);

    for (Index = 0; Index < MAXIMUM_HYPERCALL_PFN_COUNT; Index++) {
        PHYSICAL_ADDRESS    Address;

        Address = MmGetPhysicalAddress((PUCHAR)HypercallBase + (Index << PAGE_SHIFT));
        Pfn[Index] = (PFN_NUMBER)(Address.QuadPart >> PAGE_SHIFT);
    }

    __CpuId(Context->Leaf + 2, &EAX, &EBX, NULL, NULL);
    Count = EAX;
    ASSERT(Count <= MAXIMUM_HYPERCALL_PFN_COUNT);
    Msr = EBX;

    for (Index = 0; Index < Count; Index++) {
        Info("Pfn[%d]: %p\n", Index, (PVOID)Pfn[Index]);
        __writemsr(Msr, (ULONG64)Pfn[Index] << PAGE_SHIFT);
    }

    Interface->Context = Context;
    Interface->Operations = &Operations;

    Trace("<====\n");

    return STATUS_SUCCESS;

fail2:
    ASSERT(IsZeroMemory(Context, sizeof (XEN_HYPERCALL_CONTEXT)));
    __HypercallFree(Context);

fail1:
    Error("fail1 (%08x)", status);

    ASSERT(IsZeroMemory(Interface, sizeof (XEN_HYPERCALL_INTERFACE)));

    return status;
}

VOID
HypercallTeardown(
    IN OUT  PXEN_HYPERCALL_INTERFACE    Interface
    )
{
    PXEN_HYPERCALL_CONTEXT              Context = Interface->Context;

    Trace("====>\n");

    Context->Leaf = 0;

    ASSERT(IsZeroMemory(Context, sizeof (XEN_HYPERCALL_CONTEXT)));
    __HypercallFree(Context);

    RtlZeroMemory(Interface, sizeof (XEN_HYPERCALL_INTERFACE));
    
    Trace("<====\n");
}
