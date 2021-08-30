#pragma once

#include <stdlib.h>
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

typedef PVOID ExcludeContext;
typedef ExcludeContext* PExcludeContext;

NTSTATUS InitializeExcludeListContext(PExcludeContext Context);
VOID DestroyExcludeListContext(ExcludeContext Context);

NTSTATUS RemoveAllExcludeListEntries(ExcludeContext Context);
NTSTATUS AddExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FileName);
NTSTATUS RemoveExcludeListEntry(ExcludeContext Context, PUNICODE_STRING FileName);
NTSTATUS AddExcludeLocalListEntry(ExcludeContext Context, PUNICODE_STRING FileName, PUNICODE_STRING DirName);
BOOLEAN CheckExcludeListFile(ExcludeContext Context, PUNICODE_STRING FileName);
BOOLEAN CheckExcludeListLocalFile(ExcludeContext Context, PUNICODE_STRING FileName, PUNICODE_STRING DirName);

VOID PrintExcludeList(ExcludeContext Context);