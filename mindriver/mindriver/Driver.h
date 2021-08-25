#pragma once

#ifndef __DRIVER_H
#define __DRIVER_H

#ifdef MINDRV_UM
#include <winternl.h>
#include <winioctl.h>
#else
#include <wdm.h>
#endif

#define MINDRV_DEVICE_NAME L"\\Device\\MinDrv"

#ifndef MINDRV_UM
UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(MINDRV_DEVICE_NAME);
#endif

#define IOCTL_MINDRV_SET_HIDE				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_HIDE				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ALL_ACCESS)

#endif