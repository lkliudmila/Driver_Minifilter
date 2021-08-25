
#include <windows.h>
#include <wchar.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <string>

#pragma comment(lib, "ntdll")


/// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.

#define IOCTL_MINDRV_SET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ALL_ACCESS)



int __cdecl main(int argc, char* argv[])
{
	HANDLE hDevice;
	std::string filename;
	std::cout << "Enter filename: ";
	std::cin >> filename;
	std::cout<<std::endl;
	char* namechar = new char[filename.length() + 1];
	strcpy(namechar, filename.c_str());
	size_t     i;
	size_t     len;
	len = sizeof(namechar) / sizeof(char);
	wchar_t* out = new wchar_t[1 + len];
	for (i = 0; namechar[i]; i++)
		out[i] = namechar[i];
	out[i] = 0;
	std::cout << namechar << std::endl;
	std::wcout << out << std::endl;
	size_t len2;
	len2=sizeof(wchar_t)*i;
	DWORD dwBytesRead = 0;
	char ReadBuffer[50] = { 0 };

	hDevice = CreateFile(L"\\\\.\\SpotlessDeviceLink", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("Handle : %p\n", hDevice);

	DeviceIoControl(hDevice, IOCTL_MINDRV_SET_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	printf("Bytes read : %d\n", dwBytesRead);
	int ii = 0;
	std::cin >> ii;
	CloseHandle(hDevice);
	delete []out;
	system("pause");
	return 0;

}

