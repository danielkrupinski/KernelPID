#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <wdf.h>

#define PROCESS_NAME "Steam.exe"
static_assert(sizeof(PROCESS_NAME) <= 15, "Process name should not exceed 15 characters (including null terminator).");

DRIVER_INITIALIZE DriverEntry;

typedef struct _EPROCESS {
    BYTE _pad0[0x2e8];
    ULONG UniqueProcessId;
    LIST_ENTRY ActiveProcessLinks;
    BYTE _pad1[0x150];
    UCHAR ImageFileName[15];
    BYTE _pad2[0x39];
    UINT32 ActiveThreads;
} EPROCESS;

static ULONG findProcessId(const STRING* name)
{
    CONST PEPROCESS startProcess = PsGetCurrentProcess();

    PEPROCESS currentProcess = startProcess;

    do {
        if (!currentProcess->ActiveThreads)
            continue;

        STRING currentName;
        RtlInitString(&currentName, (PCSZ)currentProcess->ImageFileName);

        if (RtlEqualString(name, &currentName, FALSE))
            return currentProcess->UniqueProcessId;

    } while ((currentProcess = CONTAINING_RECORD(currentProcess->ActiveProcessLinks.Flink, EPROCESS, ActiveProcessLinks)) != startProcess);

    return 0;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS ntstatus = STATUS_SUCCESS;

    UNICODE_STRING uniName = RTL_CONSTANT_STRING(L"\\SystemRoot\\KernelPID.txt");
    OBJECT_ATTRIBUTES objAttr;

    InitializeObjectAttributes(&objAttr, &uniName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL);

    HANDLE handle;
    IO_STATUS_BLOCK ioStatusBlock;

    ntstatus = ZwCreateFile(&handle,
        GENERIC_WRITE,
        &objAttr, &ioStatusBlock, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    if (NT_SUCCESS(ntstatus)) {
        CONST STRING processName = RTL_CONSTANT_STRING(PROCESS_NAME);

        CHAR pidString[20];
        ntstatus = RtlStringCbPrintfA(pidString, _countof(pidString), "%lu\n", findProcessId(&processName));

        if (NT_SUCCESS(ntstatus)) {
            size_t length;
            ntstatus = RtlStringCbLengthA(pidString, _countof(pidString), &length);

            if (NT_SUCCESS(ntstatus))
                ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, pidString, (ULONG)length, NULL, NULL);
        }
        ZwClose(handle);
    }
    return ntstatus;
}
