#include <windows.h>
#include <Dbghelp.h>
#include <stdio.h>

#pragma comment(lib,"dbghelp.lib")


BYTE memory[0x2000];
WCHAR symbolPath[0x2000] = { 0 };
OSVERSIONINFOEXW osver = { 0 };
SYSTEM_INFO si = { 0 };

WCHAR OsId[500] = { 0 };
WCHAR returnBuf[0x2000] = { 0 };
WCHAR iniPath[MAX_PATH] = { 0 };


typedef void (WINAPI *t_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);


void WriteApiInIni(const WCHAR * name, DWORD address) //rva
{
	wsprintfW(returnBuf, L"%08X", address);
	WritePrivateProfileStringW(OsId, name, returnBuf, iniPath);
}

ULONG_PTR GetFunctionAddressPDB(HMODULE hMod, const WCHAR * name)
{
	ZeroMemory(memory, sizeof(memory));

	SYMBOL_INFOW * info = (SYMBOL_INFOW *)memory;
	info->SizeOfStruct = sizeof(SYMBOL_INFOW);
	info->MaxNameLen = MAX_SYM_NAME;
	info->ModBase = (ULONG_PTR)hMod;

	if (!SymFromNameW(GetCurrentProcess(), name, info))
	{
		printf("SymFromName %S returned error : %d\n", name, GetLastError());
		return 0;
	}

	return (ULONG_PTR)info->Address;
}

void QueryOsInfo()
{
	t_GetNativeSystemInfo _GetNativeSystemInfo = (t_GetNativeSystemInfo)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNativeSystemInfo");
	if (_GetNativeSystemInfo)
	{
		_GetNativeSystemInfo(&si);
	}
	else
	{
		GetSystemInfo(&si);
	}

	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&osver);
}

int wmain(int argc, wchar_t* argv[])
{
	QueryOsInfo();

	SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAVOR_COMPRESSED);

	WCHAR path[MAX_PATH] = { 0 };

	GetModuleFileNameW(0, path, _countof(path));
	WCHAR * temp = wcsrchr(path, L'\\');
	*temp = 0;

	wcscpy(iniPath, path);
	wcscat(iniPath, L"\\NtApiCollection.ini");

	wcscat(symbolPath, L"SRV*");
	wcscat(symbolPath, path);
	wcscat(symbolPath, L"*http://msdl.microsoft.com/download/symbols");


#ifdef _WIN64
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x64", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#else
	wsprintfW(OsId, L"%02X%02X%02X%02X%02X%02X_x86", (DWORD)osver.dwMajorVersion, (DWORD)osver.dwMinorVersion, (DWORD)osver.wServicePackMajor, (DWORD)osver.wServicePackMinor, (DWORD)osver.wProductType, (DWORD)si.wProcessorArchitecture);
#endif


	printf("OS ID: %S\n", OsId);

	if (!SymInitializeW(GetCurrentProcess(), symbolPath, TRUE))
	{
		printf("SymInitialize returned error : %d\n", GetLastError());
		return 0;
	}

	HMODULE hUser = GetModuleHandleW(L"user32.dll");

	if (hUser)
	{
		printf("User32 Base %p\n", hUser);

		ULONG_PTR addressNtUserQueryWindow = GetFunctionAddressPDB(hUser, L"NtUserQueryWindow");
		ULONG_PTR addressNtUserBuildHwndList = GetFunctionAddressPDB(hUser, L"NtUserBuildHwndList");
		ULONG_PTR addressNtUserFindWindowEx = GetFunctionAddressPDB(hUser, L"NtUserFindWindowEx");

		if (addressNtUserQueryWindow)
		{
			printf("Name %S RVA %08X\n", L"NtUserQueryWindow", (DWORD)(addressNtUserQueryWindow - (ULONG_PTR)hUser));
			printf("Name %S RVA %08X\n", L"NtUserBuildHwndList", (DWORD)(addressNtUserBuildHwndList - (ULONG_PTR)hUser));
			printf("Name %S RVA %08X\n", L"NtUserFindWindowEx", (DWORD)(addressNtUserFindWindowEx - (ULONG_PTR)hUser));

			WriteApiInIni(L"NtUserQueryWindow", (DWORD)(addressNtUserQueryWindow - (ULONG_PTR)hUser));
			WriteApiInIni(L"NtUserBuildHwndList", (DWORD)(addressNtUserBuildHwndList - (ULONG_PTR)hUser));
			WriteApiInIni(L"NtUserFindWindowEx", (DWORD)(addressNtUserFindWindowEx - (ULONG_PTR)hUser));
		}
	}

	SymCleanup(GetCurrentProcess());

	printf("\nDone!\n");

	getchar();
	return 0;
}