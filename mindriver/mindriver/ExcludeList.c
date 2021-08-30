

#include "ExcludeList.h"
#define EXCLUDE_ALLOC_TAG 'ExTG'

typedef struct _EXCLUDE_FILE_LIST_ENTRY {
	LIST_ENTRY       list;
	UNICODE_STRING name;
} EXCLUDE_FILE_LIST_ENTRY, * PEXCLUDE_FILE_LIST_ENTRY;

typedef struct _EXCLUDE_LOCAL_FILE_LIST_ENTRY {
	LIST_ENTRY       list;
	UNICODE_STRING name;
	UNICODE_STRING dirName;
} EXCLUDE_LOCAL_FILE_LIST_ENTRY, * PEXCLUDE_LOCAL_FILE_LIST_ENTRY;

typedef struct _EXCLUDE_FILE_LIST {
	LIST_ENTRY       listHead;
	FAST_MUTEX       listLock;
} EXCLUDE_FILE_LIST, * PEXCLUDE_FILE_LIST;

NTSTATUS InitializeExcludeListContext(PExcludeContext Context)
{
	PEXCLUDE_FILE_LIST list;

	list = (PEXCLUDE_FILE_LIST)ExAllocatePoolWithTag(NonPagedPool, sizeof(EXCLUDE_FILE_LIST), EXCLUDE_ALLOC_TAG);
	if (!list)
	{
		DbgPrint("Error, can't allocate memory: %p", Context);
		return STATUS_ACCESS_DENIED;
	}

	InitializeListHead(&list->listHead);
	ExInitializeFastMutex(&list->listLock);

	*Context = list;

	return STATUS_SUCCESS;
}

VOID DestroyExcludeListContext(ExcludeContext Context)
{
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	RemoveAllExcludeListEntries(Context);
	ExFreePoolWithTag(list, EXCLUDE_ALLOC_TAG);
}

NTSTATUS RemoveAllExcludeListEntries(ExcludeContext Context)
{
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&list->listHead)
	{
		PEXCLUDE_FILE_LIST_ENTRY remove = entry;
		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
		RemoveEntryList((PLIST_ENTRY)remove);
		ExFreePoolWithTag(remove, EXCLUDE_ALLOC_TAG);
	}


	ExReleaseFastMutex(&list->listLock);

	return STATUS_SUCCESS;
}

NTSTATUS AddExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FileName)
{
	enum { MAX_PATH_SIZE = 1024 };
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry, head;
	SIZE_T size;


	if (FileName->Length == 0 || FileName->Length >= MAX_PATH_SIZE)
	{
		DbgPrint("Warning, invalid string size : %d", (UINT32)FileName->Length);
		return STATUS_ACCESS_DENIED;
	}

	// Allocate and fill new list entry

	size = sizeof(EXCLUDE_FILE_LIST_ENTRY) + FileName->MaximumLength + sizeof(WCHAR);
	entry = (PEXCLUDE_FILE_LIST_ENTRY)ExAllocatePoolWithTag(NonPagedPool, size, EXCLUDE_ALLOC_TAG);
	if (!entry)
	{
		DbgPrint("Warning, exclude file list is not NULL : %p", list);
		return STATUS_ACCESS_DENIED;
	}

	RtlZeroMemory(entry, size);

	entry->name.Buffer = (PWCHAR)((PUCHAR)(&entry->name)+sizeof(UNICODE_STRING)); //(PWCH)((PCHAR)entry + sizeof(EXCLUDE_FILE_LIST_ENTRY));
	entry->name.Length = 0;
	entry->name.MaximumLength = FileName->Length;


	NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(&entry->name, FileName, FALSE)));

	head = (PEXCLUDE_FILE_LIST_ENTRY)&list->listHead;

	ExAcquireFastMutex(&list->listLock);

	InsertTailList((PLIST_ENTRY)head, (PLIST_ENTRY)entry);

	ExReleaseFastMutex(&list->listLock);


	return STATUS_SUCCESS;
}
NTSTATUS RemoveExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FileName)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&list->listHead)
	{
		if (FsRtlIsNameInExpression(&entry->name, FileName, TRUE, NULL))
		{
			RemoveEntryList((PLIST_ENTRY)entry);
			ExFreePoolWithTag(entry, EXCLUDE_ALLOC_TAG);
			status = STATUS_SUCCESS;
			break;
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&list->listLock);

	return status;
}
NTSTATUS AddExcludeLocalListEntry(ExcludeContext Context, PUNICODE_STRING FileName, PUNICODE_STRING DirName)
{

	PAGED_CODE();

	enum { MAX_PATH_SIZE = 1024 };
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_LOCAL_FILE_LIST_ENTRY entry, head;
	SIZE_T size;


	if (FileName->Length == 0 || FileName->Length >= MAX_PATH_SIZE)
	{
		DbgPrint("Warning, invalid string size : %d", (UINT32)FileName->Length);
		return STATUS_ACCESS_DENIED;
	}
	if (DirName->Length == 0 || DirName->Length >= MAX_PATH_SIZE)
	{
		DbgPrint("Warning, invalid string size : %d", (UINT32)DirName->Length);
		return STATUS_ACCESS_DENIED;
	}

	size = sizeof(EXCLUDE_LOCAL_FILE_LIST_ENTRY) + FileName->MaximumLength+ sizeof(WCHAR) +DirName->MaximumLength + sizeof(WCHAR);
	entry = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)ExAllocatePoolWithTag(NonPagedPool, size, EXCLUDE_ALLOC_TAG);
	
	if (!entry)
	{
		DbgPrint("Warning, exclude file list is not NULL : %p", list);
		return STATUS_ACCESS_DENIED;
	}

	RtlZeroMemory(entry, size);
	entry->name.Buffer = (PWCHAR)((PUCHAR)(FileName) + sizeof(UNICODE_STRING)); //(PWCH)((PCHAR)entry + sizeof(EXCLUDE_FILE_LIST_ENTRY));
	entry->name.Length = 0;
	entry->name.MaximumLength = FileName->Length;
	NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(&entry->name, FileName, FALSE)));

	entry->dirName.Buffer = (PWCHAR)((PUCHAR)(DirName)+sizeof(UNICODE_STRING)); //(PWCH)((PCHAR)entry + sizeof(EXCLUDE_FILE_LIST_ENTRY));
	entry->dirName.Length = 0;
	entry->dirName.MaximumLength = DirName->Length;
	NT_VERIFY(NT_SUCCESS(RtlUpcaseUnicodeString(&entry->dirName, DirName, FALSE)));

	head = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)&list->listHead;
	ExAcquireFastMutex(&list->listLock);
	InsertTailList((PLIST_ENTRY)head, (PLIST_ENTRY)entry);

	ExReleaseFastMutex(&list->listLock);


	return STATUS_SUCCESS;
}
NTSTATUS RemoveExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FileName, PUNICODE_STRING DirName)
{
	NTSTATUS status = STATUS_NOT_FOUND;
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_LOCAL_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)&list->listHead)
	{
		if (FsRtlIsNameInExpression(&entry->name, FileName, TRUE, NULL)&& FsRtlIsNameInExpression(&entry->dirName, DirName, TRUE, NULL))
		{
			RemoveEntryList((PLIST_ENTRY)entry);
			ExFreePoolWithTag(entry, EXCLUDE_ALLOC_TAG);
			status = STATUS_SUCCESS;
			break;
		}

		entry = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&list->listLock);

	return status;
}
BOOLEAN CheckExcludeListFile(ExcludeContext Context, PUNICODE_STRING FileName)
{
	PEXCLUDE_FILE_LIST list= (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;
	BOOLEAN result = FALSE;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&list->listHead)
	{
		if (FsRtlIsNameInExpression(&entry->name, FileName, TRUE, NULL))
		{
			result = TRUE;
			break;
		}

		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&list->listLock);

	return result;
}
BOOLEAN CheckExcludeListLocalFile(ExcludeContext Context, PUNICODE_STRING FileName, PUNICODE_STRING DirName)
{
	UNREFERENCED_PARAMETER(DirName);
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_LOCAL_FILE_LIST_ENTRY entry;
	BOOLEAN result = FALSE;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)&list->listHead)
	{
		if (FsRtlIsNameInExpression(&entry->name, FileName, TRUE, NULL)&& FsRtlIsNameInExpression(&entry->dirName, DirName, TRUE, NULL))
		{
			result = TRUE;
			break;
		}

		entry = (PEXCLUDE_LOCAL_FILE_LIST_ENTRY)entry->list.Flink;
	}

	ExReleaseFastMutex(&list->listLock);

	return result;
}

VOID PrintExcludeList(ExcludeContext Context)
{
	//UNREFERENCED_PARAMETER(print);
	
	PEXCLUDE_FILE_LIST list = (PEXCLUDE_FILE_LIST)Context;
	PEXCLUDE_FILE_LIST_ENTRY entry;

	ExAcquireFastMutex(&list->listLock);

	entry = (PEXCLUDE_FILE_LIST_ENTRY)list->listHead.Flink;
	while (entry != (PEXCLUDE_FILE_LIST_ENTRY)&list->listHead)
	{
		DbgPrint("%wZ \n", entry->name);
		entry = (PEXCLUDE_FILE_LIST_ENTRY)entry->list.Flink;
	
	}


	ExReleaseFastMutex(&list->listLock);
}

typedef struct _ELEM_LOCAL_FILE {

	UNICODE_STRING FileName;
	UNICODE_STRING FullDirName;

} ELEM_LOCAL_FILE, * PELEM_LOCAL_FILE;

typedef struct _ELEM_RULE {

	UNICODE_STRING Rule;

} ELEM_RULE, * PELEM_RULE;

typedef struct _ELEM_LOCAL_RULE {

	UNICODE_STRING Rule;
	UNICODE_STRING FullDirName;

} ELEM_LOCAL_RULE, * PELEM_LOCAL_RULE;