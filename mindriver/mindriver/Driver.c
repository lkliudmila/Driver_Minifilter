#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdlib.h>

//#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//#include "Driver.h"

#define SIOCTL_TYPE 40000


#define IOCTL_MINDRV_SET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ALL_ACCESS)


DRIVER_DISPATCH MinDrvIOCTL;
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\SpotlessDevice");
UNICODE_STRING DEVICE_SYMBOLIC_NAME = RTL_CONSTANT_STRING(L"\\??\\SpotlessDeviceLink");
void DriverUnload(PDRIVER_OBJECT dob);//for device
NTSTATUS MinDrvCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#define FILE_NAME_TAG 'myTG'

PFLT_FILTER g_FilterHandle;
PDEVICE_OBJECT g_DeviceObject;
PWCHAR prefixName;//file name for hiding
PUNICODE_STRING g_HideFileName;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS MinDrvUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS MinDrvQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS MinDrvPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

FLT_PREOP_CALLBACK_STATUS MinDrvPreDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS MinDrvPostDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS HideFilePostDirCtrl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags);


CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	/*{ IRP_MJ_CREATE,
	  0,
	  MinDrvPreCreate,
	  NULL },*/

	{ IRP_MJ_DIRECTORY_CONTROL,
	  0,
	  /*MinDrvPreDirectoryControl*/NULL,
	  HideFilePostDirCtrl },

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
        return 1;
    }

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        return 1;
    }

    ////IRP_MJ_DIRECTORY_CONTROL is an IRP-based operation.
    if (!FLT_IS_IRP_OPERATION(Data)) {
        return 1;
    }

    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length <= 0) {
        return 1;
    }

    if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL) {
        return 1;
    }

    return 0;
}

NTSTATUS MinDrvIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

    UNREFERENCED_PARAMETER(DeviceObject);

    //PIO_STACK_LOCATION pIoStackLocation;
    //PCHAR welcome = "Hello from kerneland.";
    //PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
    NT_ASSERT(DeviceObject == g_DeviceObject);
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PVOID pBuf = Irp->AssociatedIrp.SystemBuffer;
    //BOOLEAN unset;
    //PUNICODE_STRING* target;
    //UNICODE_STRING source;
    //ULONG allocationSize;
    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_MINDRV_SET_HIDE:
        if (prefixName != NULL)
        {
            ExFreePoolWithTag(prefixName, FILE_NAME_TAG);
        }
        prefixName = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, IrpSp->Parameters.DeviceIoControl.InputBufferLength, FILE_NAME_TAG);
        if (!prefixName)
        {
            DbgPrint("\nERROR\n");
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        wcscpy(prefixName, (PWCHAR)pBuf);
        DbgPrint("\nMessage received : %ws\n", (PWCHAR)pBuf);
        DbgPrint("\nName : %ws\n", prefixName);
        break;
    case IOCTL_MINDRV_UNSET_HIDE:
        //unset = TRUE;
        //target = &g_HideFileName;
        //prefixName = L"";
        break;
    default:
        Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_NOT_SUPPORTED;
    }

    /*if ((target != NULL) && (*target != NULL))
    {
        ExFreePoolWithTag(*target, FILE_NAME_TAG);
        *target = NULL;
    }

    if (unset == FALSE)
    {
        source.Buffer = (PWCHAR)Irp->AssociatedIrp.SystemBuffer;
        source.Length = (USHORT)IrpSp->Parameters.DeviceIoControl.InputBufferLength;
        source.MaximumLength = source.Length;

        allocationSize = sizeof(UNICODE_STRING) + source.MaximumLength;
        *target = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, allocationSize, FILE_NAME_TAG);
        if (*target == NULL)
        {
            Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        (*target)->Buffer = (PWCHAR)((PUCHAR)(*target) + sizeof(UNICODE_STRING));
        (*target)->MaximumLength = source.MaximumLength;
        (*target)->Length = 0;

        NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(*target, &source, FALSE)));
    }*/

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
        DbgPrint("Handle to symbolink link %wZ opened", DEVICE_SYMBOLIC_NAME);
        break;
    case IRP_MJ_CLOSE:
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


    //DriverObject->DriverUnload = DriverUnload;
    prefixName = NULL;
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
    IoDeleteDevice(g_DeviceObject);
    IoDeleteSymbolicLink(&DEVICE_SYMBOLIC_NAME);

    if (prefixName != NULL)
    {
        ExFreePoolWithTag(prefixName, FILE_NAME_TAG);
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
    //KdPrint(("\nPreCreate is running"));
    UINT32 options;
    BOOLEAN neededPrevent = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (g_HideFileName == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    options = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;
    //disposition = (Data->Iopb->Parameters.Create.Options & 0xFF000000) >> 24;

    if (!(options & FILE_DIRECTORY_FILE))
    {
        if (CheckForExcludeFile(Data, g_HideFileName))
            neededPrevent = TRUE;
    }

    if (!neededPrevent && CheckForExcludeFile(Data, g_HideFileName))
        neededPrevent = TRUE;

    KdPrint(("Pre create stop\n"));
    if (neededPrevent)
    {
        Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS MinDrvPreDirectoryControl(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (g_HideFileName == NULL)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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

FLT_POSTOP_CALLBACK_STATUS MinDrvPostDirectoryControl(PFLT_CALLBACK_DATA Data,PCFLT_RELATED_OBJECTS FltObjects,PVOID CompletionContext,FLT_POST_OPERATION_FLAGS Flags)
{
    PFILE_DIRECTORY_INFORMATION fileDirInfo, lastFileDirInfo, nextFileDirInfo;
    PFILE_FULL_DIR_INFORMATION fileFullDirInfo, lastFileFullDirInfo, nextFileFullDirInfo;
    PFILE_NAMES_INFORMATION fileNamesInfo, lastFileNamesInfo, nextFileNamesInfo;
    PFILE_BOTH_DIR_INFORMATION fileBothDirInfo, lastFileBothDirInfo, nextFileBothDirInfo;
    PFILE_ID_BOTH_DIR_INFORMATION fileIdBothDirInfo, lastFileIdBothDirInfo, nextFileIdBothDirInfo;
    PFILE_ID_FULL_DIR_INFORMATION fileIdFullDirInfo, lastFileIdFullDirInfo, nextFileIdFullDirInfo;
    UNICODE_STRING fileName;
    ULONG moveLength;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    if (g_HideFileName == NULL)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (IsUnsuccessful(Data, Flags))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
    {
    case FileDirectoryInformation:
        lastFileDirInfo = NULL;
        fileDirInfo = (PFILE_DIRECTORY_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileDirInfo->FileName;
            fileName.Length = (USHORT)fileDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileDirInfo->NextEntryOffset += fileDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;
                            nextFileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)nextFileDirInfo + nextFileDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName) + nextFileDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileDirInfo,
                            (PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileDirInfo = fileDirInfo;
            fileDirInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileDirInfo + fileDirInfo->NextEntryOffset);
            if (lastFileDirInfo == fileDirInfo)
            {
                break;
            }
        }
        break;

    case FileFullDirectoryInformation:
        lastFileFullDirInfo = NULL;
        fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileFullDirInfo->FileName;
            fileName.Length = (USHORT)fileFullDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileFullDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileFullDirInfo->NextEntryOffset += fileFullDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileFullDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileFullDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;
                            nextFileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)nextFileFullDirInfo + nextFileFullDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName) + nextFileFullDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileFullDirInfo,
                            (PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileFullDirInfo = fileFullDirInfo;
            fileFullDirInfo = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)fileFullDirInfo + fileFullDirInfo->NextEntryOffset);
            if (lastFileFullDirInfo == fileFullDirInfo)
            {
                break;
            }
        }
        break;

    case FileNamesInformation:
        lastFileNamesInfo = NULL;
        fileNamesInfo = (PFILE_NAMES_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileNamesInfo->FileName;
            fileName.Length = (USHORT)fileNamesInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileNamesInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileNamesInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileNamesInfo->NextEntryOffset += fileNamesInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileNamesInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileNamesInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileNamesInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;
                            nextFileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)nextFileNamesInfo + nextFileNamesInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName) + nextFileNamesInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileNamesInfo,
                            (PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileNamesInfo = fileNamesInfo;
            fileNamesInfo = (PFILE_NAMES_INFORMATION)((PUCHAR)fileNamesInfo + fileNamesInfo->NextEntryOffset);
            if (lastFileNamesInfo == fileNamesInfo)
            {
                break;
            }
        }
        break;

    case FileBothDirectoryInformation:
        lastFileBothDirInfo = NULL;
        fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileBothDirInfo->FileName;
            fileName.Length = (USHORT)fileBothDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileBothDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileBothDirInfo->NextEntryOffset += fileBothDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileBothDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileBothDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;
                            nextFileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)nextFileBothDirInfo + nextFileBothDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileBothDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileBothDirInfo,
                            (PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileBothDirInfo = fileBothDirInfo;
            fileBothDirInfo = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)fileBothDirInfo + fileBothDirInfo->NextEntryOffset);
            if (lastFileBothDirInfo == fileBothDirInfo)
            {
                break;
            }
        }
        break;

    case FileIdBothDirectoryInformation:
        lastFileIdBothDirInfo = NULL;
        fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileIdBothDirInfo->FileName;
            fileName.Length = (USHORT)fileIdBothDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileIdBothDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileIdBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileIdBothDirInfo->NextEntryOffset += fileIdBothDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileIdBothDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileIdBothDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileIdBothDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;
                            nextFileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)nextFileIdBothDirInfo + nextFileIdBothDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName) + nextFileIdBothDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileIdBothDirInfo,
                            (PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            //
            // Advance to the next directory info
            //
            lastFileIdBothDirInfo = fileIdBothDirInfo;
            fileIdBothDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)fileIdBothDirInfo + fileIdBothDirInfo->NextEntryOffset);
            if (lastFileIdBothDirInfo == fileIdBothDirInfo)
            {
                break;
            }
        }
        break;

    case FileIdFullDirectoryInformation:
        lastFileIdFullDirInfo = NULL;
        fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        for (;;)
        {
            //
            // Create a unicode string from file name so we can use FsRtl
            //
            fileName.Buffer = fileIdFullDirInfo->FileName;
            fileName.Length = (USHORT)fileIdFullDirInfo->FileNameLength;
            fileName.MaximumLength = fileName.Length;

            //
            // Check if this is a match on our hide file name
            //
            if (FsRtlIsNameInExpression(g_HideFileName, &fileName, TRUE, NULL))
            {
                //
                // Skip this entry
                //
                if (lastFileIdFullDirInfo != NULL)
                {
                    //
                    // This is not the first entry
                    //
                    if (fileIdFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Just point the last info's offset to the next info
                        //
                        lastFileIdFullDirInfo->NextEntryOffset += fileIdFullDirInfo->NextEntryOffset;
                    }
                    else
                    {
                        //
                        // This is the last entry
                        //
                        lastFileIdFullDirInfo->NextEntryOffset = 0;
                    }
                }
                else
                {
                    //
                    // This is the first entry
                    //
                    if (fileIdFullDirInfo->NextEntryOffset != 0)
                    {
                        //
                        // Calculate the length of the whole list
                        //
                        nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
                        moveLength = 0;
                        while (nextFileIdFullDirInfo->NextEntryOffset != 0)
                        {
                            //
                            // We use the FIELD_OFFSET macro because FileName is declared as FileName[1] which means that
                            // we can't just do sizeof(FILE_DIRECTORY_INFORMATION) + nextFileDirInfo->FileNameLength.
                            //
                            moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;
                            nextFileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)nextFileIdFullDirInfo + nextFileIdFullDirInfo->NextEntryOffset);
                        }

                        //
                        // Add the final entry
                        //
                        moveLength += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName) + nextFileIdFullDirInfo->FileNameLength;

                        //
                        // We need to move everything forward.
                        // NOTE: RtlMoveMemory (memove) is required for overlapping ranges like this one.
                        //
                        RtlMoveMemory(
                            fileIdFullDirInfo,
                            (PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset,
                            moveLength);
                    }
                    else
                    {
                        //
                        // This is the first and last entry, so there's nothing to return
                        //
                        Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
                        return FLT_POSTOP_FINISHED_PROCESSING;
                    }
                }
            }

            lastFileIdFullDirInfo = fileIdFullDirInfo;
            fileIdFullDirInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)fileIdFullDirInfo + fileIdFullDirInfo->NextEntryOffset);
            if (lastFileIdFullDirInfo == fileIdFullDirInfo)
            {
                break;
            }

        }
        break;

    default:

        NT_ASSERT(FALSE);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS HideFilePostDirCtrl(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags)
{
	ULONG nextOffset = 0;
	int modified = 0;
	int removedAllEntries = 1;
	//PVOID SafeBuffer;


    //PWCHAR prefixName = (PWCHAR)prefixName2;//file name for hiding

	//PFILE_ID_BOTH_DIR_INFORMATION  currentFileInfo = 0;
	//PFILE_ID_BOTH_DIR_INFORMATION  nextFileInfo = 0;
	//PFILE_ID_BOTH_DIR_INFORMATION  previousFileInfo = 0;


	//UNICODE_STRING fileName;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (IsUnsuccessful(Data, Flags))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
    if (prefixName == NULL)
    {

        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    DbgPrint("\nName : %ws\n", prefixName);

   /* if (_wcsnicmp(L"l", prefixName, wcslen(prefixName)) == 0)
    {
        KdPrint(("end==========\n"));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }*/

	switch (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass)
	{
	case FileIdFullDirectoryInformation:
	{
		PVOID SafeBuffer;
		PFILE_ID_FULL_DIR_INFORMATION  currentFileInfo = 0;
		PFILE_ID_FULL_DIR_INFORMATION  nextFileInfo = 0;
		PFILE_ID_FULL_DIR_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_ID_FULL_DIR_INFORMATION)SafeBuffer;

		previousFileInfo = currentFileInfo;

		do
		{
			nextOffset = currentFileInfo->NextEntryOffset;


			nextFileInfo = (PFILE_ID_FULL_DIR_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
			if ((previousFileInfo == currentFileInfo) &&
				(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0))//&& (currentFileInfo->FileNameLength == 2)))
			{
				KdPrint(("--->First\n"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0)//&& (currentFileInfo->FileNameLength == 2))
			{
				KdPrint(("--->Second\n"));
				if (nextOffset == 0)
				{
					previousFileInfo->NextEntryOffset = 0;
				}
				else
				{
					previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
				}

				modified = 1;
			}
			else
			{
				removedAllEntries = 0;
				previousFileInfo = currentFileInfo;
			}
			currentFileInfo = nextFileInfo;
		} while (nextOffset != 0);

		if (modified)
		{
			if (removedAllEntries)
			{
				Data->IoStatus.Status = STATUS_NO_MORE_FILES;
			}
			else
			{
				FltSetCallbackDataDirty(Data);
			}
		}
	}
		break;
	case FileIdBothDirectoryInformation:
	{
		PVOID SafeBuffer;
		PFILE_ID_BOTH_DIR_INFORMATION  currentFileInfo = 0;
		PFILE_ID_BOTH_DIR_INFORMATION  nextFileInfo = 0;
		PFILE_ID_BOTH_DIR_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_ID_BOTH_DIR_INFORMATION)SafeBuffer;

		previousFileInfo = currentFileInfo;

		do
		{
			//Byte offset of the next FILE_BOTH_DIR_INFORMATION entry
			nextOffset = currentFileInfo->NextEntryOffset;


			nextFileInfo = (PFILE_ID_BOTH_DIR_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
			if ((previousFileInfo == currentFileInfo) &&
				(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0 ))//&& (currentFileInfo->FileNameLength == 2)))
			{
				KdPrint(("--->First"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}
			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0 )//&& (currentFileInfo->FileNameLength == 2))
			{
				KdPrint(("--->Second"));
				if (nextOffset == 0)
				{
					previousFileInfo->NextEntryOffset = 0;
				}
				else
				{
					previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
				}

				modified = 1;
			}
			else
			{
				removedAllEntries = 0;
				previousFileInfo = currentFileInfo;
			}
		
			currentFileInfo = nextFileInfo;
		} while (nextOffset != 0);

		if (modified)
		{
			if (removedAllEntries)
			{
				Data->IoStatus.Status = STATUS_NO_MORE_FILES;
			}
			else
			{
				FltSetCallbackDataDirty(Data);
			}
		}
	}
		break;
	case FileBothDirectoryInformation:
	{
		PVOID SafeBuffer;
		PFILE_BOTH_DIR_INFORMATION  currentFileInfo = 0;
		PFILE_BOTH_DIR_INFORMATION  nextFileInfo = 0;
		PFILE_BOTH_DIR_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_BOTH_DIR_INFORMATION)SafeBuffer;

			previousFileInfo = currentFileInfo;

			do
			{
				//Byte offset of the next FILE_BOTH_DIR_INFORMATION entry
				nextOffset = currentFileInfo->NextEntryOffset;


				nextFileInfo = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
				if ((previousFileInfo == currentFileInfo) &&
					(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0 ))//&&(currentFileInfo->FileNameLength == 2)))
				{
					KdPrint(("--->First"));
					RtlCopyMemory(currentFileInfo->FileName, L".", 2);
					currentFileInfo->FileNameLength = 0;
					FltSetCallbackDataDirty(Data);
					return FLT_POSTOP_FINISHED_PROCESSING;
				}

				//If the conditions are met, hide it
				if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0)// && (currentFileInfo->FileNameLength == 2))
				{
					KdPrint(("--->Second"));
					if (nextOffset == 0)
					{
						previousFileInfo->NextEntryOffset = 0;
					}
					else
					{
						previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
					}

					modified = 1;
				}
				else
				{
					removedAllEntries = 0;
					previousFileInfo = currentFileInfo;
				}
				currentFileInfo = nextFileInfo;
			} while (nextOffset != 0);

			if (modified)
			{
				if (removedAllEntries)
				{
					Data->IoStatus.Status = STATUS_NO_MORE_FILES;
				}
				else
				{
					FltSetCallbackDataDirty(Data);
				}
			}
	}
	break;
	case FileDirectoryInformation:
	{	PVOID SafeBuffer;
		PFILE_DIRECTORY_INFORMATION  currentFileInfo = 0;
		PFILE_DIRECTORY_INFORMATION  nextFileInfo = 0;
		PFILE_DIRECTORY_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_DIRECTORY_INFORMATION)SafeBuffer;

		previousFileInfo = currentFileInfo;

		do
		{
			nextOffset = currentFileInfo->NextEntryOffset;


			nextFileInfo = (PFILE_DIRECTORY_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
			if ((previousFileInfo == currentFileInfo) &&
				(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0))//&&(currentFileInfo->FileNameLength == 2)))
			{
				KdPrint(("--->First"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0) //&& (currentFileInfo->FileNameLength == 2))
			{
				KdPrint(("--->Second"));
				if (nextOffset == 0)
				{
					previousFileInfo->NextEntryOffset = 0;
				}
				else
				{
					previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
				}

				modified = 1;
			}
			else
			{
				removedAllEntries = 0;
				previousFileInfo = currentFileInfo;
			}
			currentFileInfo = nextFileInfo;
		} while (nextOffset != 0);

		if (modified)
		{
			if (removedAllEntries)
			{
				Data->IoStatus.Status = STATUS_NO_MORE_FILES;
			}
			else
			{
				FltSetCallbackDataDirty(Data);
			}
		}
	}
	break;
		break;
	case FileFullDirectoryInformation:
	{
		PVOID SafeBuffer;
		PFILE_FULL_DIR_INFORMATION  currentFileInfo = 0;
		PFILE_FULL_DIR_INFORMATION  nextFileInfo = 0;
		PFILE_FULL_DIR_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_FULL_DIR_INFORMATION)SafeBuffer;

		previousFileInfo = currentFileInfo;

		do
		{
			nextOffset = currentFileInfo->NextEntryOffset;


			nextFileInfo = (PFILE_FULL_DIR_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
			if ((previousFileInfo == currentFileInfo) &&
				(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0 ))//&&(currentFileInfo->FileNameLength == 2)))
			{
				KdPrint(("--->First"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0) //&& (currentFileInfo->FileNameLength == 2))
			{
				KdPrint(("--->Second"));
				if (nextOffset == 0)
				{
					previousFileInfo->NextEntryOffset = 0;
				}
				else
				{
					previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
				}

				modified = 1;
			}
			else
			{
				removedAllEntries = 0;
				previousFileInfo = currentFileInfo;
			}
			currentFileInfo = nextFileInfo;
		} while (nextOffset != 0);

		if (modified)
		{
			if (removedAllEntries)
			{
				Data->IoStatus.Status = STATUS_NO_MORE_FILES;
			}
			else
			{
				FltSetCallbackDataDirty(Data);
			}
		}
	}
		break;
	case FileNamesInformation:
	{
		PVOID SafeBuffer;
		PFILE_NAMES_INFORMATION  currentFileInfo = 0;
		PFILE_NAMES_INFORMATION  nextFileInfo = 0;
		PFILE_NAMES_INFORMATION  previousFileInfo = 0;
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
			SafeBuffer = MmGetSystemAddressForMdlSafe(
				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			SafeBuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (SafeBuffer == NULL)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		currentFileInfo = (PFILE_NAMES_INFORMATION)SafeBuffer;

		previousFileInfo = currentFileInfo;

		do
		{
			nextOffset = currentFileInfo->NextEntryOffset;


			nextFileInfo = (PFILE_NAMES_INFORMATION)((PCHAR)(currentFileInfo)+nextOffset);
			if ((previousFileInfo == currentFileInfo) &&
				(_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0))//&&(currentFileInfo->FileNameLength == 2)))
			{
				KdPrint(("--->First"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0) //&& (currentFileInfo->FileNameLength == 2))
			{
				KdPrint(("--->Second"));
				if (nextOffset == 0)
				{
					previousFileInfo->NextEntryOffset = 0;
				}
				else
				{
					previousFileInfo->NextEntryOffset = (ULONG)((PCHAR)currentFileInfo - (PCHAR)previousFileInfo) + nextOffset;
				}

				modified = 1;
			}
			else
			{
				removedAllEntries = 0;
				previousFileInfo = currentFileInfo;
			}
			currentFileInfo = nextFileInfo;
		} while (nextOffset != 0);

		if (modified)
		{
			if (removedAllEntries)
			{
				Data->IoStatus.Status = STATUS_NO_MORE_FILES;
			}
			else
			{
				FltSetCallbackDataDirty(Data);
			}
		}
	}
	
		break;
	default:
		//FltReleaseFileNameInformation(fltName);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}


	return FLT_POSTOP_FINISHED_PROCESSING;
}
