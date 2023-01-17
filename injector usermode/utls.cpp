#include "utls.h"

#include "crypter.h"

#include <Windows.h>
#include <TlHelp32.h>


unsigned long long GetModuleBaseAddress(unsigned long procId, const wchar_t* modName)
{
	unsigned long long modBaseAddr = 0;
	HANDLE hSnap = li(CreateToolhelp32Snapshot)(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (li(Module32FirstW)(hSnap, &modEntry))
		{
			do
			{
				if (!li(_wcsicmp)(modEntry.szModule, modName))
				{
					modBaseAddr = (unsigned long long)modEntry.modBaseAddr;
					break;
				}
			} while (li(Module32Next)(hSnap, &modEntry));
		}
	}
	li(CloseHandle)(hSnap);
	return modBaseAddr;
}
unsigned long long get_var_offset(void* var)
{
	return unsigned long long(var) - GetModuleBaseAddress(unsigned long(li(GetCurrentProcessId)()), xorstr_(L"ConsoleApplication1.exe"));// IQ || too lazy to look for how to get the base address of executable, it was the easiest way
}
//template T
unsigned long long get_updated_var(void* var)
{
	return *(unsigned long long*)((unsigned long long)var);
}


