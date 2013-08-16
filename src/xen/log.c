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

#pragma warning(disable:4152)   // nonstandard extension, function/data pointer conversion in expression

#include <ntddk.h>
#include <stdlib.h>
#include <xen.h>

#include "log.h"
#include "assert.h"
#include "high.h"

#define LOG_BUFFER_SIZE 256

static UCHAR        LogBuffer[LOG_BUFFER_SIZE];
static ULONG        LogOffset;
static HIGH_LOCK    LogLock;

static FORCEINLINE
__drv_maxIRQL(HIGH_LEVEL)
__drv_raisesIRQL(HIGH_LEVEL)
__drv_savesIRQL
KIRQL
__LogAcquireBuffer(
    VOID
    )
{
    return __AcquireHighLock(&LogLock);
}

#define LOG_PORT_XEN    0xE9
#define LOG_PORT_QEMU   0x12

static DECLSPEC_NOINLINE VOID
__drv_maxIRQL(HIGH_LEVEL)
__drv_requiresIRQL(HIGH_LEVEL)
__LogReleaseBuffer(
    IN  USHORT                      Port,
    IN  __drv_restoresIRQL KIRQL    Irql
    )
{
    __outbytestring(Port, LogBuffer, LogOffset);

    RtlZeroMemory(LogBuffer, LogOffset);
    LogOffset = 0;

    ReleaseHighLock(&LogLock, Irql);
}

static FORCEINLINE VOID
__LogPut(
    IN  CHAR    Character
    )
{
    ASSERT(LogOffset < LOG_BUFFER_SIZE);

    LogBuffer[LogOffset++] = Character;
}

static DECLSPEC_NOINLINE PCHAR
LogFormatNumber(
    IN  PCHAR       Buffer,
    IN  ULONGLONG   Value,
    IN  UCHAR       Base,
    IN  BOOLEAN     UpperCase
    )
{
    ULONGLONG       Next = Value / Base;

    if (Next != 0)
        Buffer = LogFormatNumber(Buffer, Next, Base, UpperCase);

    Value %= Base;

    if (Value < 10)
        *Buffer++ = '0' + (CHAR)Value;
    else
        *Buffer++ = ((UpperCase) ? 'A' : 'a') + (CHAR)(Value - 10);

    *Buffer = '\0';

    return Buffer;
}

#define LOG_FORMAT_NUMBER(_Arguments, _Type, _Character, _Buffer)                               \
        do {                                                                                    \
            U ## _Type  _Value = va_arg((_Arguments), U ## _Type);                              \
            BOOLEAN     _UpperCase = FALSE;                                                     \
            UCHAR       _Base = 0;                                                              \
            ULONG       _Index = 0;                                                             \
                                                                                                \
            if ((_Character) == 'd' && (_Type)_Value < 0) {                                     \
                _Value = -((_Type)_Value);                                                      \
                (_Buffer)[_Index++] = '-';                                                      \
            }                                                                                   \
                                                                                                \
            switch (_Character) {                                                               \
            case 'o':                                                                           \
                _Base = 8;                                                                      \
                break;                                                                          \
                                                                                                \
            case 'd':                                                                           \
            case 'u':                                                                           \
                _Base = 10;                                                                     \
                break;                                                                          \
                                                                                                \
            case 'p':                                                                           \
            case 'X':                                                                           \
                _UpperCase = TRUE;                                                              \
                /* FALLTHRU */                                                                  \
                                                                                                \
            case 'x':                                                                           \
                _Base = 16;                                                                     \
                break;                                                                          \
            }                                                                                   \
                                                                                                \
            (VOID) LogFormatNumber(&(_Buffer)[_Index], (ULONGLONG)_Value, _Base, _UpperCase);   \
        } while (FALSE)

static DECLSPEC_NOINLINE VOID
LogWriteBuffer(
    IN  LONG        Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    CHAR            Character;

    while ((Character = *Format++) != '\0') {
        UCHAR   Pad = 0;
        UCHAR   Long = 0;
        BOOLEAN Wide = FALSE;
        BOOLEAN ZeroPrefix = FALSE;
        BOOLEAN OppositeJustification = FALSE;
        
        if (Character != '%') {
            __LogPut(Character);
            goto loop;
        }

        Character = *Format++;
        ASSERT(Character != '\0');

        if (Character == '-') {
            OppositeJustification = TRUE;
            Character = *Format++;
            ASSERT(Character != '\0');
        }

        if (isdigit((unsigned char)Character)) {
            ZeroPrefix = (Character == '0') ? TRUE : FALSE;

            while (isdigit((unsigned char)Character)) {
                Pad = (Pad * 10) + (Character - '0');
                Character = *Format++;
                ASSERT(Character != '\0');
            }
        }

        while (Character == 'l') {
            Long++;
            Character = *Format++;
            ASSERT(Character == 'd' ||
                   Character == 'u' ||
                   Character == 'o' ||
                   Character == 'x' ||
                   Character == 'X' ||
                   Character == 'l');
        }
        ASSERT3U(Long, <=, 2);

        while (Character == 'w') {
            Wide = TRUE;
            Character = *Format++;
            ASSERT(Character == 'c' ||
                   Character == 's' ||
                   Character == 'Z');
        }

        switch (Character) {
        case 'c': {
            if (Wide) {
                WCHAR   Value;
                Value = va_arg(Arguments, WCHAR);

                __LogPut((CHAR)Value);
            } else { 
                CHAR    Value;

                Value = va_arg(Arguments, CHAR);

                __LogPut(Value);
            }
            break;
        }
        case 'p':
            ZeroPrefix = TRUE;
            Pad = sizeof (ULONG_PTR) * 2;
            Long = sizeof (ULONG_PTR) / sizeof (ULONG);
            /* FALLTHRU */

        case 'd':
        case 'u':
        case 'o':
        case 'x':
        case 'X': {
            CHAR    Buffer[23]; // Enough for 8 bytes in octal plus the NUL terminator
            ULONG   Length;
            ULONG   Index;

            if (Long == 2)
                LOG_FORMAT_NUMBER(Arguments, LONGLONG, Character, Buffer);
            else
                LOG_FORMAT_NUMBER(Arguments, LONG, Character, Buffer);

            Length = (ULONG)strlen(Buffer);
            if (!OppositeJustification) {
                while (Pad > Length) {
                    __LogPut((ZeroPrefix) ? '0' : ' ');
                    --Pad;
                }
            }
            for (Index = 0; Index < Length; Index++)
                __LogPut(Buffer[Index]);
            if (OppositeJustification) {
                while (Pad > Length) {
                    __LogPut(' ');
                    --Pad;
                }
            }

            break;
        }
        case 's': {
            if (Wide) {
                PWCHAR  Value = va_arg(Arguments, PWCHAR);
                ULONG   Length;
                ULONG   Index;

                if (Value == NULL)
                    Value = L"(null)";

                Length = (ULONG)wcslen(Value);

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut((CHAR)Value[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }
            } else {
                PCHAR   Value = va_arg(Arguments, PCHAR);
                ULONG   Length;
                ULONG   Index;

                if (Value == NULL)
                    Value = "(null)";

                Length = (ULONG)strlen(Value);

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Value[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }
            }

            break;
        }
        case 'Z': {
            if (Wide) {
                PUNICODE_STRING Value = va_arg(Arguments, PUNICODE_STRING);
                PWCHAR          Buffer;
                ULONG           Length;
                ULONG           Index;

                if (Value == NULL) {
                    Buffer = L"(null)";
                    Length = sizeof ("(null)") - 1;
                } else {
                    Buffer = Value->Buffer;
                    Length = Value->Length / sizeof (WCHAR);
                }

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut((CHAR)Buffer[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }
            } else {
                PANSI_STRING Value = va_arg(Arguments, PANSI_STRING);
                PCHAR        Buffer;
                ULONG        Length;
                ULONG        Index;

                if (Value == NULL) {
                    Buffer = "(null)";
                    Length = sizeof ("(null)") - 1;
                } else {
                    Buffer = Value->Buffer;
                    Length = Value->Length / sizeof (CHAR);
                }

                if (OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }

                for (Index = 0; Index < Length; Index++)
                    __LogPut(Buffer[Index]);

                if (!OppositeJustification) {
                    while (Pad > Length) {
                        __LogPut(' ');
                        --Pad;
                    }
                }
            }

            break;
        }
        default:
            __LogPut(Character);
            break;
        }

loop:
        if (--Count == 0)
            break;
    }
}

static FORCEINLINE VOID
__LogXenCchVPrintf(
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    KIRQL           Irql;

    Irql = __LogAcquireBuffer();

    LogWriteBuffer(__min(Count, LOG_BUFFER_SIZE),
                  Format,
                  Arguments);

    __LogReleaseBuffer(LOG_PORT_XEN, Irql);
}

static FORCEINLINE VOID
__LogQemuCchVPrintf(
    IN  ULONG       Count,
    IN  const CHAR  *Format,
    IN  va_list     Arguments
    )
{
    KIRQL           Irql;

    Irql = __LogAcquireBuffer();

    LogWriteBuffer(__min(Count, LOG_BUFFER_SIZE),
                  Format,
                  Arguments);

    __LogReleaseBuffer(LOG_PORT_QEMU, Irql);
}

VOID
LogCchVPrintf(
    IN  LOG_DESTINATION Destination,
    IN  ULONG           Count,
    IN  const CHAR      *Format,
    IN  va_list         Arguments
    )
{
    switch (Destination) {
    case LOG_DESTINATION_QEMU:
        __LogQemuCchVPrintf(Count, Format, Arguments);
        break;

    case LOG_DESTINATION_XEN:
        __LogXenCchVPrintf(Count, Format, Arguments);
        break;

    default:
        ASSERT(FALSE);
        break;
    }
}

VOID
LogVPrintf(
    IN  LOG_DESTINATION Destination,
    IN  const CHAR      *Format,
    IN  va_list         Arguments
    )
{
    LogCchVPrintf(Destination, LOG_BUFFER_SIZE, Format, Arguments);
}

VOID
LogCchPrintf(
    IN  LOG_DESTINATION Destination,
    IN  ULONG           Count,
    IN  const CHAR      *Format,
    ...
    )
{
    va_list             Arguments;

    va_start(Arguments, Format);
    LogCchVPrintf(Destination, Count, Format, Arguments);
    va_end(Arguments);
}

VOID
LogPrintf(
    IN  LOG_DESTINATION Destination,
    IN  const CHAR      *Format,
    ...
    )
{
    va_list             Arguments;

    va_start(Arguments, Format);
    LogCchVPrintf(Destination, LOG_BUFFER_SIZE, Format, Arguments);
    va_end(Arguments);
}

typedef VOID
(*DBG_PRINT_CALLBACK)(
    PANSI_STRING    Ansi,
    ULONG           ComponentId,
    ULONG           Level
    );

static DECLSPEC_NOINLINE VOID
LogDebugPrint(
    IN  PANSI_STRING    Ansi,
    IN  ULONG           ComponentId,
    IN  ULONG           Level
    )
{
    if (Ansi->Length == 0 || Ansi->Buffer == NULL)
        return;

    if (ComponentId == DPFLTR_IHVDRIVER_ID) {
        switch (Level) {
        case DPFLTR_ERROR_LEVEL:
            LogCchPrintf(LOG_DESTINATION_QEMU, Ansi->Length, Ansi->Buffer);
            break;

        case DPFLTR_WARNING_LEVEL:
            LogCchPrintf(LOG_DESTINATION_QEMU, Ansi->Length, Ansi->Buffer);
            break;

        case DPFLTR_INFO_LEVEL:
            LogCchPrintf(LOG_DESTINATION_QEMU, Ansi->Length, Ansi->Buffer);
            break;

        case DPFLTR_TRACE_LEVEL:
            LogCchPrintf(LOG_DESTINATION_XEN, Ansi->Length, Ansi->Buffer);
            break;

        default:
            break;
        }
    } else {
        LogCchPrintf(LOG_DESTINATION_XEN, Ansi->Length, Ansi->Buffer);
    }
}

BOOLEAN CallbackInstalled;

VOID
LogTeardown(
    VOID
    )
{
    if (CallbackInstalled) {
        (VOID) DbgSetDebugPrintCallback(LogDebugPrint, FALSE); 
        CallbackInstalled = FALSE;
    }
}

VOID
LogInitialize(
    VOID)
{
    InitializeHighLock(&LogLock);

    if (!CallbackInstalled) {
        NTSTATUS    status;

        status = DbgSetDebugPrintCallback(LogDebugPrint, TRUE);
        CallbackInstalled = NT_SUCCESS(status) ? TRUE : FALSE;
    }
}
