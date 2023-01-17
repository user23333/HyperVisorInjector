static unsigned long	  target_pid		= 0xBC444;
static unsigned long	  raw_size			= 0xBC440;
static unsigned long long raw_ptr			= 0xBC450;
static unsigned long long asm_executor_base	= 0xBC458;
static unsigned long long execute_status	= 0xBC448;
static unsigned long long just_nothing		= 0xBC438;

#pragma optimize("", off)
// discord skeng#9524

#include "utls.h"
#include "dll_image.h"

#include <stdio.h>
#include <Windows.h>

using namespace std;

#define DEBUG_MODE // if you remove it, then all static offsets will shift to an unknown value :) || update: nope, fixed :))
int main()
{
	raw_size = sizeof(rawData);	// <- IDA user danger
	raw_ptr = unsigned long long(rawData); // <- IDA user danger
	unsigned long target_thread_id = li(GetWindowThreadProcessId)(FindWindow(xorstr_(L"UnityWndClass"), NULL), &target_pid); //window class name of game ( might have to change inside of driver too)
#ifdef DEBUG_MODE
	printf(xorstr_("#define target_pid_offset 0x%X\n"), get_var_offset(&target_pid));
	printf(xorstr_("#define target_raw_size_offset 0x%X //%d\n"), get_var_offset(&raw_size), raw_size);
	printf(xorstr_("#define target_raw_ptr_offset 0x%X //0x%X\n"), get_var_offset(&raw_ptr), raw_ptr);
	printf(xorstr_("#define asm_executor_base_offset 0x%X\n"), get_var_offset(&asm_executor_base));
	printf(xorstr_("#define execute_status_offset 0x%X\n"), get_var_offset(&execute_status));
	printf(xorstr_("#define just_nothing_offset 0x%X\n"), get_var_offset(&just_nothing));
#endif // DEBUG_MODE
#ifndef DEBUG_MODE
	
#endif // !DEBUG_MODE

	if (target_pid && target_thread_id) 
	{
		while (!get_updated_var(&asm_executor_base)); 
		HMODULE nt_dll = li(LoadLibraryW)(xorstr_(L"ntdll.dll"));
#ifdef DEBUG_MODE
		printf(xorstr_("[info] Target memory section: 0x%p\n"), asm_executor_base);
#endif // DEBUG_MODE
#ifndef DEBUG_MODE
		//printf(xorstr_("[info] Target memory section found   | ret code - 0x%p\n"), just_nothing);
#endif // !DEBUG_MODE	

		HHOOK h_hook = li(SetWindowsHookEx)(/*ANY HOOKID HERE*/WH_MOUSE, (HOOKPROC)asm_executor_base, nt_dll, target_thread_id);
		execute_status = 0x10101;
		while (get_updated_var(&execute_status) == 0x10101);

		li(UnhookWindowsHookEx)(h_hook);

		printf(xorstr_("[GoodLuck] Execution complete, enjoy :)\n"));
	}
	getchar();
}

