#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER filterHandle;
PWCHAR prefixName = L"OPENME.txt";//file name for hiding


NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath);
NTSTATUS PtUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
HideFilePostDirCtrl(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	NULL,
	HideFilePostDirCtrl },

	{ IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration =
{
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks
	PtUnload,                           //  MiniFilterUnload
	NULL,                               //  InstanceSetup
	NULL,                               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	status = FltRegisterFilter(DriverObject, &FilterRegistration, &filterHandle);

	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(filterHandle);

		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(filterHandle);
		}
	}

	return status;
}

NTSTATUS PtUnload(__in FLT_FILTER_UNLOAD_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Flags);
	PAGED_CODE();

	FltUnregisterFilter(filterHandle);

	return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS HideFilePostDirCtrl(
	__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	ULONG nextOffset = 0;
	int modified = 0;
	int removedAllEntries = 1;
	//PVOID SafeBuffer;



	//PFILE_ID_BOTH_DIR_INFORMATION  currentFileInfo = 0;
	//PFILE_ID_BOTH_DIR_INFORMATION  nextFileInfo = 0;
	//PFILE_ID_BOTH_DIR_INFORMATION  previousFileInfo = 0;


	//UNICODE_STRING fileName;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)){
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!NT_SUCCESS(Data->IoStatus.Status)){
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	////IRP_MJ_DIRECTORY_CONTROL is an IRP-based operation.
	if (!FLT_IS_IRP_OPERATION(Data)){
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length <= 0){
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}



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
				KdPrint(("--->First"));
				RtlCopyMemory(currentFileInfo->FileName, L".", 2);
				currentFileInfo->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(currentFileInfo->FileName, prefixName, wcslen(prefixName)) == 0)//&& (currentFileInfo->FileNameLength == 2))
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