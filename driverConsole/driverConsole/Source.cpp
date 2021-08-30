
#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <tchar.h>
#include <stdio.h>
#include <iostream>
#include <string>

using namespace std;
#pragma comment(lib, "ntdll")


/// Device type
#define SIOCTL_TYPE 40000

// The IOCTL function codes from 0x800 to 0xFFF are for customer use.

#define IOCTL_MINDRV_SET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x800, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_HIDE				CTL_CODE(SIOCTL_TYPE, 0x801, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_SET_APPPROCESS		    CTL_CODE(SIOCTL_TYPE, 0x802, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_SET_LOCAL_HIDE			CTL_CODE(SIOCTL_TYPE, 0x803, METHOD_BUFFERED, FILE_ALL_ACCESS)
#define IOCTL_MINDRV_UNSET_LOCAL_HIDE		CTL_CODE(SIOCTL_TYPE, 0x804, METHOD_BUFFERED, FILE_ALL_ACCESS)

DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}
void menu()
{
	cout << "'e' - close the program" << endl;
	cout << "'F' - set or unset global file name for hiding" << endl;
	cout << "'f' - set or unset local file name for hiding" << endl;
}

void globalFileName(HANDLE hDevice)
{
	cout << "	's'- set file name for hiding" << endl;
	cout << "	'u'- unset filename for hiding" << endl;
	char control;
	cin >> control;
	switch (control)
	{
	case 's':
	{
		std::string filename;
		size_t     i;
		size_t     len;

		std::cout << "Enter filename: ";
		std::cin >> filename;
		std::cout << std::endl;

		char* namechar = new char[filename.length() + 1];
		strcpy(namechar, filename.c_str());

		len = sizeof(namechar) / sizeof(char);
		wchar_t* out = new wchar_t[1 + len];

		for (i = 0; namechar[i]; i++)
			out[i] = namechar[i];
		out[i] = 0;

		std::cout << namechar << std::endl;
		std::wcout << out << std::endl;
		size_t len2;
		len2 = sizeof(wchar_t) * i;
		DWORD dwBytesRead = 0;
		char ReadBuffer[50] = { 0 };

		DeviceIoControl(hDevice, IOCTL_MINDRV_SET_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		delete[]out;
	}
		break;
	case 'u':
	{
		std::string filename;
		size_t     i;
		size_t     len;

		std::cout << "Enter filename: ";
		std::cin >> filename;
		std::cout << std::endl;

		char* namechar = new char[filename.length() + 1];
		strcpy(namechar, filename.c_str());

		len = sizeof(namechar) / sizeof(char);
		wchar_t* out = new wchar_t[1 + len];

		for (i = 0; namechar[i]; i++)
			out[i] = namechar[i];
		out[i] = 0;

		std::cout << namechar << std::endl;
		std::wcout << out << std::endl;
		size_t len2;
		len2 = sizeof(wchar_t) * i;
		DWORD dwBytesRead = 0;
		char ReadBuffer[50] = { 0 };

		DeviceIoControl(hDevice, IOCTL_MINDRV_UNSET_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		delete[]out;
	}
		break;
	default:
		break;
	}
}
void localFileName(HANDLE hDevice)
{
	WIN32_FIND_DATA f;
	string path;
	cout << "Enter directory (example: C:\\Windows\\*): ";
	cin >> path;
	cout << endl;
	wstring wsTmp(path.begin(), path.end());
	//std::wstring DATA_DIR = L"C:\\*";
	std::wstring DATA_DIR = wsTmp;
	HANDLE h = FindFirstFile((LPCWSTR)(DATA_DIR.c_str()), &f);
	if (h != INVALID_HANDLE_VALUE)
	{
		int i = 0;
		do
		{
			++i;
			printf("%x)%S\n",i, f.cFileName);
		} while (FindNextFile(h, &f));
		FindClose(h);
	}

	cout << "	's'- set local file name for hiding" << endl;
	cout << "	'u'- unset local filename for hiding" << endl;
	char control;
	cin >> control;
	switch (control)
	{
	case 's':
	{
		std::string filename;
		size_t     i;
		size_t     len;

		std::cout << "Enter filename: ";
		std::cin >> filename;
		std::cout << std::endl;

		char* namechar = new char[filename.length() + 1];
		strcpy(namechar, filename.c_str());

		len = sizeof(namechar) / sizeof(char);
		wchar_t* out = new wchar_t[1 + len];

		for (i = 0; namechar[i]; i++)
			out[i] = namechar[i];
		out[i] = 0;

		std::cout << namechar << std::endl;
		std::wcout << out << std::endl;
		size_t len2;
		len2 = sizeof(wchar_t) * i;
		DWORD dwBytesRead = 0;
		char ReadBuffer[50] = { 0 };

		DeviceIoControl(hDevice, IOCTL_MINDRV_SET_LOCAL_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		delete[]out;
	}
	break;
	case 'u':
	{
		std::string filename;
		size_t     i;
		size_t     len;

		std::cout << "Enter filename: ";
		std::cin >> filename;
		std::cout << std::endl;

		char* namechar = new char[filename.length() + 1];
		strcpy(namechar, filename.c_str());

		len = sizeof(namechar) / sizeof(char);
		wchar_t* out = new wchar_t[1 + len];

		for (i = 0; namechar[i]; i++)
			out[i] = namechar[i];
		out[i] = 0;

		std::cout << namechar << std::endl;
		std::wcout << out << std::endl;
		size_t len2;
		len2 = sizeof(wchar_t) * i;
		DWORD dwBytesRead = 0;
		char ReadBuffer[50] = { 0 };

		DeviceIoControl(hDevice, IOCTL_MINDRV_UNSET_LOCAL_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
		delete[]out;
	}
	break;
	default:
		break;
	}
}
void work()
{
	HANDLE hDevice;
	DWORD* ppid;
	DWORD pid = MyGetProcessId(TEXT("driverConsole.exe"));
	ppid = &pid;
	hDevice = CreateFile(L"\\\\.\\MinDriverDeviceLink", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	printf("Handle : %p\n", hDevice);
	DeviceIoControl(hDevice, IOCTL_MINDRV_SET_APPPROCESS, ppid, sizeof(ppid), NULL, 0, NULL, NULL);
	char control='s';
	while (control != 'e')
	{
		menu();
		cin >> control;

		switch (control)
		{
		case 'F':
			globalFileName(hDevice);
			break;
		case 'f':
			localFileName(hDevice);
			break;
		case 'e':
			break;
		default:
			break;
		}

	}
	CloseHandle(hDevice);
	system("pause");

}

int __cdecl main(int argc, char* argv[])
{

	//WIN32_FIND_DATA f;
	//string path;
	//cin >> path;
	//wstring wsTmp(path.begin(), path.end());
	////std::wstring DATA_DIR = L"C:\\*";
	//std::wstring DATA_DIR = wsTmp;
	//HANDLE h = FindFirstFile((LPCWSTR)(DATA_DIR.c_str()), &f);
	//if (h != INVALID_HANDLE_VALUE)
	//{
	//	do
	//	{
	//		printf("%S\n", f.cFileName);
	//	} while (FindNextFile(h, &f));
	//	FindClose(h);
	//}
	/*
	std::string filename;
	size_t     i;
	size_t     len;

	std::cout << "Enter filename: ";
	std::cin >> filename;
	std::cout << std::endl;

	char* namechar = new char[filename.length() + 1];
	strcpy(namechar, filename.c_str());

	len = sizeof(namechar) / sizeof(char);
	wchar_t* out = new wchar_t[1 + len];

	for (i = 0; namechar[i]; i++)
		out[i] = namechar[i];
	out[i] = 0;

	std::cout << namechar << std::endl;
	std::wcout << out << std::endl;
	size_t len2;
	len2 = sizeof(wchar_t) * i;
	DWORD dwBytesRead = 0;
	char ReadBuffer[50] = { 0 };

	DeviceIoControl(hDevice, IOCTL_MINDRV_SET_LOCAL_HIDE, out, len2, ReadBuffer, sizeof(ReadBuffer), &dwBytesRead, NULL);
	int ii = 0;
	std::cin >> ii;
	delete[]out;
	CloseHandle(hDevice);*/
	work();
	return 0;
}

