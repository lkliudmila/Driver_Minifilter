
#include "ExcludeList.h"
#include "Helper.h"
#include <stdio.h>
#include <stdlib.h>
//#include <direct.h>

//#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
#pragma comment(lib,"msvcrtd.lib")
#define SIOCTL_TYPE 40000


#define IOCTL_MINDRV_SET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_SET_APPPROCESS		    CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_SET_LOCAL_HIDE			CTL_CODE(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_LOCAL_HIDE		CTL_CODE(SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_ALL_ACCESS)

DRIVER_DISPATCH MinDrvIOCTL;
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MinDriverDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\MinDriverDeviceLink");
NTSTATUS MinDrvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#define FILE_NAME_TAG 'myTG'

PWCHAR prefixName =L"OPENME.TXT";
ULONG g_applicationprocess;
PFLT_FILTER g_FilterHandle;
PDEVICE_OBJECT g_DeviceObject;
PUNICODE_STRING g_HideFileName;
ExcludeContext g_excludeFileContext;
ExcludeContext g_excludeLocalFileContext;
PUNICODE_STRING g_currentDirectory;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS MinDrvUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS MinDrvQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS MinDrvPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS MinDrvPreDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MinDrvPostDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

//FLT_POSTOP_CALLBACK_STATUS FltDirCtrlPostOperation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);


NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);
NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName);


CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{	{ IRP_MJ_CREATE,
	  0,
	  MinDrvPreCreate,
	  NULL },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      MinDrvPreDirectoryControl,
      MinDrvPostDirectoryControl },
      //FltDirCtrlPostOperation},

	{ IRP_MJ_OPERATION_END }
};


CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks
	MinDrvUnload,                       //  MiniFilterUnload
	NULL,                               //  InstanceSetup
	MinDrvQueryTeardown,                //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};



VOID GetFileName(PUNICODE_STRING FilePath, PUNICODE_STRING FileName)
{
    ULONG i;

    *FileName = *FilePath;

    i = FileName->Length / sizeof(WCHAR);
    if ((i == 0) || (FileName->Buffer[i - 1] == L'\\'))
    {
        FileName->Length = 0;
        return;
    }

    for (;;)
    {
        i--;

        if (FileName->Buffer[i] == L'\\')
        {
            //
            // Adjust the string 
            //
            FileName->Buffer += i;
            FileName->Buffer += (ULONG)1;
            FileName->Length -= (USHORT)((i + (ULONG)1) * sizeof(WCHAR));
            return;
        }

        if (i == 0)
        {
            return;
        }
    }
}

BOOLEAN CheckForExcludeFile(PFLT_CALLBACK_DATA Data, PUNICODE_STRING PotentialMatch)
{
    NTSTATUS status;
    UNICODE_STRING fileName;
    PFLT_FILE_NAME_INFORMATION fileNameInformation;
    BOOLEAN match;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInformation);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    GetFileName(&fileNameInformation->Name, &fileName);

    if (fileName.Length != 0)
    {
        match = FsRtlIsNameInExpression(PotentialMatch, &fileName, TRUE, NULL);
    }
    else
    {
        match = FALSE;
    }

    FltReleaseFileNameInformation(fileNameInformation);

    return match;
}

BOOLEAN IsUnsuccessful(PFLT_CALLBACK_DATA Data, FLT_POST_OPERATION_FLAGS Flags)
{
    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        return TRUE;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return TRUE;
    }

    ////IRP_MJ_DIRECTORY_CONTROL is an IRP-based operation.
    if (!FLT_IS_IRP_OPERATION(Data)) {
        return TRUE;
    }

    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length <= 0) {
        return TRUE;
    }

    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL) {
        return TRUE;
    }

    return FALSE;
}

NTSTATUS MinDrvIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NT_ASSERT(DeviceObject == g_DeviceObject);

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_MINDRV_SET_HIDE:
    {
        if (g_HideFileName != NULL)
        {
            ExFreePoolWithTag(g_HideFileName, FILE_NAME_TAG);
        }

        ULONG allocationSize;
        UNICODE_STRING source;
        source.Buffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
        source.Length = (USHORT)IrpSp->Parameters.DeviceIoControl.InputBufferLength;
        source.MaximumLength = source.Length;

        allocationSize = sizeof(UNICODE_STRING) + source.MaximumLength;
        g_HideFileName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);

        if (!g_HideFileName)
        {
            DbgPrint("\nERROR\n");
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_HideFileName->Buffer = (PWCHAR)((PUCHAR)(g_HideFileName)+sizeof(UNICODE_STRING));
        g_HideFileName->MaximumLength = source.MaximumLength;
        g_HideFileName->Length = 0;

        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(g_HideFileName, &source, FALSE)));

        DbgPrint("\nMessage received : %ws\n", (PWCHAR)pBuf);
        DbgPrint("Unicode string: %wZ\n", g_HideFileName);
        NTSTATUS st;
        st = AddExcludeListEntry(g_excludeFileContext, g_HideFileName);
        if (!NT_SUCCESS(st))
        {
            DbgPrint("ERROR");
            break;
        };
        PrintExcludeList(g_excludeFileContext);
    }
    break;
    case IOCTL_MINDRV_UNSET_HIDE:
    {   
        if (g_HideFileName != NULL)
        {
            ExFreePoolWithTag(g_HideFileName, FILE_NAME_TAG);
        }

        ULONG allocationSize;
        UNICODE_STRING source;
        source.Buffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
        source.Length = (USHORT)IrpSp->Parameters.DeviceIoControl.InputBufferLength;
        source.MaximumLength = source.Length;

        allocationSize = sizeof(UNICODE_STRING) + source.MaximumLength;
        g_HideFileName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);

        if (!g_HideFileName)
        {
            DbgPrint("\nERROR\n");
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_HideFileName->Buffer = (PWCHAR)((PUCHAR)(g_HideFileName)+sizeof(UNICODE_STRING));
        g_HideFileName->MaximumLength = source.MaximumLength;
        g_HideFileName->Length = 0;

        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(g_HideFileName, &source, FALSE)));

        DbgPrint("\nMessage received : %ws\n", (PWCHAR)pBuf);
        DbgPrint("Unicode string: %wZ\n", g_HideFileName);
        NTSTATUS st;
        st = RemoveExcludeListEntry(g_excludeFileContext, g_HideFileName);
        if (!NT_SUCCESS(st))
        {
            DbgPrint("ERROR");
            break;
        };
        PrintExcludeList(g_excludeFileContext);
    }
        break;
    case IOCTL_MINDRV_SET_APPPROCESS:
    {
        g_applicationprocess = *((PULONG)Irp->AssociatedIrp.SystemBuffer);
        
    }
    break;
    case IOCTL_MINDRV_SET_LOCAL_HIDE:
    {
        if (g_HideFileName != NULL)
        {
            ExFreePoolWithTag(g_HideFileName, FILE_NAME_TAG);
        }

        ULONG allocationSize;
        UNICODE_STRING source;
        source.Buffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
        source.Length = (USHORT)IrpSp->Parameters.DeviceIoControl.InputBufferLength;
        source.MaximumLength = source.Length;

        allocationSize = sizeof(UNICODE_STRING) + source.MaximumLength;
        g_HideFileName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);

        if (!g_HideFileName)
        {
            DbgPrint("\nERROR\n");
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_HideFileName->Buffer = (PWCHAR)((PUCHAR)(g_HideFileName)+sizeof(UNICODE_STRING));
        g_HideFileName->MaximumLength = source.MaximumLength;
        g_HideFileName->Length = 0;

        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(g_HideFileName, &source, FALSE)));

        DbgPrint("\nMessage received : %ws\n", (PWCHAR)pBuf);
        DbgPrint("Unicode string: %wZ\n", g_HideFileName);
        NTSTATUS st;
        st = AddExcludeLocalListEntry(g_excludeLocalFileContext, g_HideFileName, g_currentDirectory);
        if (!NT_SUCCESS(st))
        {
            DbgPrint("ERROR");
            break;
        };
        //PrintExcludeList(g_excludeFileContext);
    }
    break;
    default:
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    }


    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


NTSTATUS MinDrvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stackLocation = NULL;
    stackLocation = IoGetCurrentIrpStackLocation(Irp);

    switch (stackLocation->MajorFunction)
    {
    case IRP_MJ_CREATE:
        g_applicationprocess = 0;
        DbgPrint("Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
        break;
    case IRP_MJ_CLOSE:
        g_applicationprocess = 0;
        DbgPrint("Handle to symbolink link %wZ closed", DEVICE_SYMBOLIC_NAME);
        break;
    default:
        break;
    }

    Irp->IoStatus.Information = 0;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("DriverEntry() has been called\n");

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &g_FilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status))
    {
        status = FltStartFiltering(g_FilterHandle);

        if (!NT_SUCCESS(status))
        {
            FltUnregisterFilter(g_FilterHandle);
            DbgPrint("Filter registration status: 0x%x\n", status);

                return status;
            
        }
    }

   // DbgPrint("Filter registration status: 0x%x\n", status);
   // UNICODE_STRING str;
    status = InitializeExcludeListContext(&g_excludeFileContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Exclude file list initialization failed with code:%08x", status);
        return status;
    }

    g_HideFileName = NULL;
    ULONG allocationSize;
    UNICODE_STRING str;
    RtlInitUnicodeString(&str, prefixName);

    allocationSize = sizeof(UNICODE_STRING) + str.MaximumLength;
    g_HideFileName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);
    g_HideFileName->Buffer = (PWCHAR)((PUCHAR)(&str)+sizeof(UNICODE_STRING));
    g_HideFileName->MaximumLength = str.MaximumLength;
    g_HideFileName->Length = 0;

    NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(g_HideFileName, &str, FALSE)));
    status= AddExcludeListEntry(g_excludeFileContext, g_HideFileName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ERROR");
    }
   
    status = InitializeExcludeListContext(&g_excludeLocalFileContext);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("Exclude local file list initialization failed with code:%08x", status);
        return status;
    }
    g_currentDirectory = NULL;
    g_applicationprocess = 0;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MinDrvIoctl;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = MinDrvCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MinDrvCreateClose;
    //g_HideFileName = NULL;
    

    status = IoCreateDevice(DriverObject, 0, &DEVICE_NAME, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
     {
        DbgPrint("Could not create device %wZ", DEVICE_NAME);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }
    else
    {
        DbgPrint("Device %wZ created", DEVICE_NAME);
    }

    status = IoCreateSymbolicLink(&DEVICE_SYMBOLIC_NAME, &DEVICE_NAME);
    if (NT_SUCCESS(status))
    {
        DbgPrint("Symbolic link %wZ created", DEVICE_SYMBOLIC_NAME);
    }
    else
    {

        DbgPrint("Error creating symbolic link %wZ", DEVICE_SYMBOLIC_NAME);
        FltUnregisterFilter(g_FilterHandle);
        return status;
    }
    

    return STATUS_SUCCESS;
}

NTSTATUS MinDrvUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	FltUnregisterFilter(g_FilterHandle);
    DestroyExcludeListContext(g_excludeFileContext);
    DestroyExcludeListContext(g_excludeLocalFileContext);
    IoDeleteDevice(g_DeviceObject);
    IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);

    if (g_HideFileName != NULL)
    {
        ExFreePoolWithTag(g_HideFileName, FILE_NAME_TAG);
    }
    if (g_currentDirectory != NULL)
    {
        ExFreePoolWithTag(g_currentDirectory, FILE_NAME_TAG);
    }
	return STATUS_SUCCESS;
}

NTSTATUS MinDrvQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS MinDrvPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);


    NTSTATUS status;
    UNICODE_STRING fileName;
    PFLT_FILE_NAME_INFORMATION fileNameInformation;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &fileNameInformation);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    GetFileName(&fileNameInformation->Name, &fileName);
    //DbgPrint("%wZ\n", fileName);
    if (CheckExcludeListFile(g_excludeFileContext, &fileName))
    {
        DbgPrint("%wZ\n", fileName);
        Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
        FltReleaseFileNameInformation(fileNameInformation);
        return FLT_PREOP_COMPLETE;
    }
    else
    {
        FltReleaseFileNameInformation(fileNameInformation);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

FLT_PREOP_CALLBACK_STATUS MinDrvPreDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);


	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
    if (FltGetRequestorProcessId(Data) == g_applicationprocess)
    {
        if (g_currentDirectory != NULL)
        {
            ExFreePoolWithTag(g_currentDirectory, FILE_NAME_TAG);
        }
        NTSTATUS status;
        PFLT_FILE_NAME_INFORMATION fltName;
        status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
        if (!NT_SUCCESS(status))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

       ULONG allocationSize = sizeof(UNICODE_STRING) + fltName->Name.MaximumLength;
        g_currentDirectory = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);

        if (!g_currentDirectory)
        {
            DbgPrint("\nERROR\n");
            FltReleaseFileNameInformation(fltName);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        g_currentDirectory->Buffer = (PWCHAR)((PUCHAR)(g_currentDirectory)+sizeof(UNICODE_STRING));
        g_currentDirectory->Length = 0;
        g_currentDirectory->MaximumLength = fltName->Name.MaximumLength;
        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(g_currentDirectory, &fltName->Name, FALSE)));
        DbgPrint("PID: %u and %u\n", FltGetRequestorProcessId(Data), g_applicationprocess);

        DbgPrint("Unicode string: %wZ\n", g_currentDirectory);
        FltReleaseFileNameInformation(fltName);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

   // KdPrint(("Unicode string: %wZ\n", g_HideFileName));
    
	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdFullDirectoryInformation:
	case FileIdBothDirectoryInformation:
	case FileBothDirectoryInformation:
	case FileDirectoryInformation:
	case FileFullDirectoryInformation:
	case FileNamesInformation:

		break;

	default:

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS MinDrvPostDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    PFLT_PARAMETERS parameters = &Data->Iopb->Parameters;
    PFLT_FILE_NAME_INFORMATION fltName;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (IsUnsuccessful(Data, Flags))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &fltName);
    if (!NT_SUCCESS(status))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
   // DbgPrint("%wZ\n",&fltName->ParentDir);
    status = STATUS_SUCCESS;
    switch (parameters->DirectoryControl.QueryDirectory.FileInformationClass)
    {
    case FileFullDirectoryInformation:
        status = CleanFileFullDirectoryInformation((PFILE_FULL_DIR_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    case FileBothDirectoryInformation:
        status = CleanFileBothDirectoryInformation((PFILE_BOTH_DIR_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    case FileDirectoryInformation:
        status = CleanFileDirectoryInformation((PFILE_DIRECTORY_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    case FileIdFullDirectoryInformation:
        status = CleanFileIdFullDirectoryInformation((PFILE_ID_FULL_DIR_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    case FileIdBothDirectoryInformation:
        status = CleanFileIdBothDirectoryInformation((PFILE_ID_BOTH_DIR_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    case FileNamesInformation:
        status = CleanFileNamesInformation((PFILE_NAMES_INFORMATION)parameters->DirectoryControl.QueryDirectory.DirectoryBuffer, fltName);
        break;
    }

    Data->IoStatus.Status = status;

    FltReleaseFileNameInformation(fltName);


    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS CleanFileFullDirectoryInformation(PFILE_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN matched, search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;
        if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            matched = FALSE;
        }
        else
        {
            matched = (CheckExcludeListFile(g_excludeFileContext, &fileName)
                ||CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName,&fltName->Name));

            //DbgPrint("%wZ\n", fltName->Name);
        }

        if (matched)
        {
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_FULL_DIR_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_FULL_DIR_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return STATUS_SUCCESS;
}

NTSTATUS CleanFileBothDirectoryInformation(PFILE_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN matched, search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;

        if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            matched = FALSE;
        }
        else
        {
            matched = (CheckExcludeListFile(g_excludeFileContext, &fileName)
                || CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName, &fltName->Name));
        }
       

        if (matched)
        {
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_BOTH_DIR_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return STATUS_SUCCESS;
}

NTSTATUS CleanFileDirectoryInformation(PFILE_DIRECTORY_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_DIRECTORY_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN matched, search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;


        if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            matched = FALSE;
        }
        else
        {
            matched = (CheckExcludeListFile(g_excludeFileContext, &fileName)
                || CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName, &fltName->Name));
        }

        if (matched)
        {
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_DIRECTORY_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_DIRECTORY_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdFullDirectoryInformation(PFILE_ID_FULL_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_ID_FULL_DIR_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN matched, search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;

        if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            matched = FALSE;
        }
        else
        {
            matched = (CheckExcludeListFile(g_excludeFileContext, &fileName)
                || CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName, &fltName->Name));
        }

        if (matched)
        {
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_ID_FULL_DIR_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return STATUS_SUCCESS;
}

NTSTATUS CleanFileIdBothDirectoryInformation(PFILE_ID_BOTH_DIR_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_ID_BOTH_DIR_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN matched, search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;

        if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            matched = FALSE;
        }
        else
        {
            matched = (CheckExcludeListFile(g_excludeFileContext, &fileName)
                || CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName, &fltName->Name));
        }

        if (matched)
        {
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_ID_BOTH_DIR_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return status;
}

NTSTATUS CleanFileNamesInformation(PFILE_NAMES_INFORMATION info, PFLT_FILE_NAME_INFORMATION fltName)
{
    PFILE_NAMES_INFORMATION nextInfo, prevInfo = NULL;
    UNICODE_STRING fileName;
    UINT32 offset, moveLength;
    BOOLEAN search;
    NTSTATUS status = STATUS_SUCCESS;

    offset = 0;
    search = TRUE;

    do
    {
        fileName.Buffer = info->FileName;
        fileName.Length = (USHORT)info->FileNameLength;
        fileName.MaximumLength = (USHORT)info->FileNameLength;

        if ((CheckExcludeListFile(g_excludeFileContext, &fileName)
                || CheckExcludeListLocalFile(g_excludeLocalFileContext, &fileName, &fltName->Name)))
        {
            //DbgPrint("%wZ\n", fltName->Name);
            BOOLEAN retn = FALSE;

            if (prevInfo != NULL)
            {
                if (info->NextEntryOffset != 0)
                {
                    prevInfo->NextEntryOffset += info->NextEntryOffset;
                    offset = info->NextEntryOffset;
                }
                else
                {
                    prevInfo->NextEntryOffset = 0;
                    status = STATUS_SUCCESS;
                    retn = TRUE;
                }

                RtlFillMemory(info, sizeof(FILE_NAMES_INFORMATION), 0);
            }
            else
            {
                if (info->NextEntryOffset != 0)
                {
                    nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
                    moveLength = 0;
                    while (nextInfo->NextEntryOffset != 0)
                    {
                        moveLength += nextInfo->NextEntryOffset;
                        nextInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextInfo + nextInfo->NextEntryOffset);
                    }

                    moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextInfo->FileNameLength;
                    RtlMoveMemory(info, (PUCHAR)info + info->NextEntryOffset, moveLength);//continue
                }
                else
                {
                    status = STATUS_NO_MORE_ENTRIES;
                    retn = TRUE;
                }
            }

            DbgPrint("Removed from query: %wZ\\%wZ", &fltName->Name, &fileName);

            if (retn)
                return status;

            info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);
            continue;
        }

        offset = info->NextEntryOffset;
        prevInfo = info;
        info = (PFILE_NAMES_INFORMATION)((PCHAR)info + offset);

        if (offset == 0)
            search = FALSE;
    } while (search);

    return STATUS_SUCCESS;
}
