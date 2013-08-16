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

#ifndef _XEN_HYPERCALL_INTERFACE_H
#define _XEN_HYPERCALL_INTERFACE_H

#define DEFINE_HYPERCALL_OPERATIONS                                                 \
        HYPERCALL_OPERATION(VOID,                                                   \
                            Acquire,                                                \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context                    \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(VOID,                                                   \
                            Release,                                                \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context                    \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            EventChannelOp,                                         \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument                   \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            HvmOp,                                                  \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument                   \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            MemoryOp,                                               \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument                   \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            SchedOp,                                                \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument                   \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            XenVersion,                                             \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument                   \
                            )                                                       \
                            )                                                       \
        HYPERCALL_OPERATION(LONG_PTR,                                               \
                            GrantTableOp,                                           \
                            (                                                       \
                            IN PXEN_HYPERCALL_CONTEXT    Context,                   \
                            IN ULONG                     Command,                   \
                            IN PVOID                     Argument,                  \
                            IN ULONG                     Count                      \
                            )                                                       \
                            )

typedef struct _XEN_HYPERCALL_CONTEXT   XEN_HYPERCALL_CONTEXT, *PXEN_HYPERCALL_CONTEXT;

#define HYPERCALL_OPERATION(_Type, _Name, _Arguments) \
        _Type (*HYPERCALL_ ## _Name) _Arguments;

typedef struct _XEN_HYPERCALL_OPERATIONS {
    DEFINE_HYPERCALL_OPERATIONS
} XEN_HYPERCALL_OPERATIONS, *PXEN_HYPERCALL_OPERATIONS;

#undef HYPERCALL_OPERATION

typedef struct _XEN_HYPERCALL_INTERFACE  XEN_HYPERCALL_INTERFACE, *PXEN_HYPERCALL_INTERFACE;

// 65080355-2399-416f-a02f-8091aaceef4d
DEFINE_GUID(GUID_HYPERCALL_INTERFACE, 
            0x65080355,
            0x2399,
            0x4164,
            0xa0,
            0x2f,
            0x80,
            0x91,
            0xaa,
            0xce,
            0xef,
            0x4d);

#define HYPERCALL_INTERFACE_VERSION 1

#define HYPERCALL_OPERATIONS(_Interface) \
        (PXEN_HYPERCALL_OPERATIONS *)((ULONG_PTR)(_Interface))

#define HYPERCALL_CONTEXT(_Interface) \
        (PXEN_HYPERCALL_CONTEXT *)((ULONG_PTR)(_Interface) + sizeof (PVOID))

#define HYPERCALL(_Operation, _Interface, ...) \
        (*HYPERCALL_OPERATIONS(_Interface))->HYPERCALL_ ## _Operation((*HYPERCALL_CONTEXT(_Interface)), __VA_ARGS__)

#endif  // _XEN_HYPERCALL_INTERFACE_H

