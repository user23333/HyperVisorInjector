#include "global.h"

#include <minwindef.h>
//#define InitialStack			0x28 
//#define WIN1909
#ifdef WIN1909
#define KernelStack				0x58 //_KTHREAD
#define VCreateTime				0x600//_ETHREAD
#define StartAddress			0x620//_ETHREAD
#define CID						0x648//_ETHREAD
#define Win32StartAddress		0x6a0//_ETHREAD
#define ExitStatus				0x710//_ETHREAD
#define KernelStackReference	0x724//_ETHREAD
#endif // WIN1909
#ifndef WIN1909
#define KernelStack				0x58 //_KTHREAD
#define VCreateTime				0x430//_ETHREAD
#define StartAddress			0x450//_ETHREAD
#define CID						0x478//_ETHREAD
#define Win32StartAddress		0x4d0//_ETHREAD
#define ExitStatus				0x548//_ETHREAD
#define KernelStackReference	0x55c//_ETHREAD
#endif //!WIN1909

//#define target_pid_offset 0xC8044
//#define target_raw_size_offset 0xC8040 //780800
//#define target_raw_ptr_offset 0xC8050 //0xC5418040
//#define asm_executor_base_offset 0xC8058
//#define execute_status_offset 0xC8048
//#define just_nothing_offset 0xC8038
#define target_pid_offset 0xBC444
#define target_raw_size_offset 0xBC440 //736768
#define target_raw_ptr_offset 0xBC450 //0x21C28040
#define asm_executor_base_offset 0xBC458
#define execute_status_offset 0xBC448
#define just_nothing_offset 0xBC438




#define remote_call_dll_main_size 92 //sizeof(dll_stub)
#define NT_HEADER(ModBase) (PIMAGE_NT_HEADERS)((ULONG64)(ModBase) + ((PIMAGE_DOS_HEADER)(ModBase))->e_lfanew)

unsigned char remote_call_dll_main[92] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

typedef struct _main_struct
{
	int status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_struct;
void WaitGame(PVOID StartContext, PVOID StackPreserve) {
	PVOID CurrentThread = PVOID(ImpCall(KeGetCurrentThread));
	InterruptedThreadArray = EPtr(CurrentThread);//PKTHREAD
	PreservedStackArray = EPtr(StackPreserve);

	//useless
	PVOID StartThreadAddress = (PVOID)RVA(FindPattern(EPtr(KBase), E("PAGE"), E("48 89 44 24 ? 48 8D 05 ? ? ? ? 48 89 54 24 ?")), 12);//any random value, just for addres spoofing
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(KernelStack)))) = EPtr(EPtr(0));
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(VCreateTime)))) = EPtr(EPtr(2147483247));
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(StartAddress)))) = StartThreadAddress;
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(CID)))) = EPtr(EPtr(0));
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(Win32StartAddress)))) = StartThreadAddress;
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(ExitStatus)))) = EPtr(EPtr(0));
	PVOID DefaultStackRef = *(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(KernelStackReference))));
	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(KernelStackReference)))) = EPtr(EPtr(0));
	//useless

	HANDLE usermode_pid = 0;
WaitProcess:
	usermode_pid = GetProcessId(E("ConsoleApplication1.exe"));
	if (!usermode_pid) { Sleep(500); goto WaitProcess; }

	PEPROCESS usermode_pep = nullptr;
	ImpCall(PsLookupProcessByProcessId, usermode_pid, &usermode_pep);

	unsigned long target_pid = 0;
	unsigned long raw_size = 0;
	PVOID usermodebase = 0;
	PVOID local_raw_image = 0;
	PVOID usermode_raw_image = 0;
	auto CurrentProcess = KiSwapProcess(usermode_pep); //simple APC swap
	{
		usermodebase = GetUserModuleBase(usermode_pep, E("ConsoleApplication1.exe"));
	point1:
		MemCpy(&target_pid, PVOID(ULONG64(usermodebase) + target_pid_offset), sizeof(unsigned long));
		if (target_pid == 0) { Sleep(500); goto point1; }
		MemCpy(&raw_size, PVOID(ULONG64(usermodebase) + target_raw_size_offset), sizeof(unsigned long));
		MemCpy(&usermode_raw_image, PVOID(ULONG64(usermodebase) + target_raw_ptr_offset), sizeof(unsigned long long));

		local_raw_image = KAlloc(raw_size);
		MemCpy(local_raw_image, usermode_raw_image, raw_size);

	}
	KiSwapProcess(CurrentProcess);

	PEPROCESS target_pep = nullptr;
	ImpCall(PsLookupProcessByProcessId, (HANDLE)target_pid, &target_pep);
	//process_dirbase_cr3 = EPtr(GetProcessCr3(target_pep));

	PIMAGE_NT_HEADERS dll_nt_head = NT_HEADER(local_raw_image); // any dll without imports

	PVOID allocate_base, alloc_shell_code;

	KiSwapProcess(target_pep);
	{
		AllocateMemory(dll_nt_head->OptionalHeader.SizeOfImage, allocate_base);
		AllocateMemory(4096, alloc_shell_code);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(dll_nt_head);
		for (unsigned short sec_cnt = 0; sec_cnt < dll_nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
		{
			MemCpy((PVOID)((uintptr_t)allocate_base + section->VirtualAddress), (PVOID)((uintptr_t)local_raw_image + section->PointerToRawData), section->SizeOfRawData);
		}
	
	}
	KiSwapProcess(CurrentProcess);



	unsigned long  shell_size = remote_call_dll_main_size + sizeof(main_struct);

	PVOID alloc_local = KAlloc(shell_size);
	RtlCopyMemory(alloc_local, &remote_call_dll_main, remote_call_dll_main_size);
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + remote_call_dll_main_size;
	*(uintptr_t*)((uintptr_t)alloc_local + 0x6) = shell_data;

	main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + remote_call_dll_main_size);
	main_data->dll_base = (HINSTANCE)allocate_base;
	main_data->fn_dll_main = ((uintptr_t)allocate_base + dll_nt_head->OptionalHeader.AddressOfEntryPoint);

	KiSwapProcess(target_pep);
	{
		MemCpy(alloc_shell_code, alloc_local, shell_size);
	}
	KiSwapProcess(CurrentProcess);
	KFree(alloc_local);

	KiSwapProcess(usermode_pep); //simple APC swap
	{
		MemCpy(PVOID(ULONG64(usermodebase) + asm_executor_base_offset), &alloc_shell_code, sizeof(unsigned long long));
		unsigned long long exec_stat = 0;
	point: MemCpy(&exec_stat, PVOID(ULONG64(usermodebase) + execute_status_offset), sizeof(unsigned long long));
		if (exec_stat != 0x10101)goto point;
		Sleep(5000);

		exec_stat = 0x20202;
		MemCpy(PVOID(ULONG64(usermodebase) + execute_status_offset), &exec_stat, sizeof(unsigned long long));
	}
	KiSwapProcess(CurrentProcess);


	KiSwapProcess(target_pep); //simple APC swap
	{
		FreeMemory(PVOID(alloc_shell_code), shell_size);
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(dll_nt_head);
		for (WORD sec_cnt = 0; sec_cnt < dll_nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
		{
			if (section->SizeOfRawData == 0)continue;
			if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
			{
				PVOID zero_memory = KAlloc(section->SizeOfRawData);
				MemZero(zero_memory, section->SizeOfRawData);
				MemCpy(PVOID(ULONG64(allocate_base) + section->VirtualAddress), zero_memory, section->SizeOfRawData);
				KFree(zero_memory);
			}
		}
	}
	KiSwapProcess(CurrentProcess);
	KFree(local_raw_image);

	ImpCall(ObfDereferenceObject, target_pep);
	ImpCall(ObfDereferenceObject, usermode_pep);

	*(PVOID*)((ULONG64)CurrentThread + ULONG64(EPtr(EPtr(KernelStackReference)))) = DefaultStackRef;
	ImpCall(PsTerminateSystemThread, 0);
}

#define PTE_SHIFT 3
#define VA_SHIFT (63 - 47)
#define MiGetVirtualAddressMappedByPte(PTE) ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - EPtr<ULONG64>(PTEBase)) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))
PVOID MmAllocateIndependentPages(PVOID KBase, ULONG PageCount)
{
	auto MiSystemPartition = (PVOID)RVA(FindPattern(KBase, E(".text"), E("0F 85 ? ? ? ? 48 8D 05 ? ? ? ? 4C 3B D0")), 13);
	auto MiGetPage = (PVOID)RVA(FindPattern(KBase, E(".text"), E("48 8B 0C C8 E8 ? ? ? ? 48 83 F8 FF")), 9);
	auto MiRemovePhysicalMemory = (PVOID)RVA(FindPattern(KBase, E(".text"), E("E8 ? ? ? ? 48 83 3D ? ? ? ? ? 75 E9 48 8D ?")), 5);
	auto MiSystemPteInfo = (PVOID)RVA(FindPattern(KBase, E(".text"), E("4C 2B D1 48 8D 0D ? ? ? ?")), 10);
	auto MiReservePtes = (PVOID)RVA(FindPattern(KBase, E(".text"), E("48 8B 80 ? ? ? ? 48 89 45 ? E8 ? ? ? ?")), 16);
	MMPTE* PTE = CallPtr<MMPTE*>(MiReservePtes, MiSystemPteInfo, PageCount);
	if (!PTE) return nullptr;
	auto VA = MiGetVirtualAddressMappedByPte(PTE);
	for (SIZE_T i = 0; i < PageCount; i++)
	{
	NewTry:
		auto PFN = CallPtr<ULONG64>(MiGetPage, MiSystemPartition, 0ull, 8ull);
		if (PFN == -1) goto NewTry;
		ULONG64 PfnSize = 0x1000; PfnSize = PfnSize >> 12;
		CallPtr<void>(MiRemovePhysicalMemory, PFN, PfnSize);
		PTE->u.Hard.Valid = 1;
		PTE->u.Hard.Owner = 0;
		PTE->u.Hard.Write = 1;
		PTE->u.Hard.NoExecute = 0;
		PTE->u.Hard.PageFrameNumber = PFN;
		++PTE;
	}
	return VA;
}
void InitializeThread(PVOID KBase) {
	UCHAR ThreadStartShellcode[] = { 0xFA, 0x48, 0x89, 0xE2, 0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	UCHAR* ShellcodeBase = (UCHAR*)KAlloc(sizeof(ThreadStartShellcode), NonPagedPool);
	MemCpy(ShellcodeBase, &ThreadStartShellcode[0], sizeof(ThreadStartShellcode));
	SIZE_T StackSize = 0x1000 * 16;
	auto RealStack = MmAllocateIndependentPages(KBase, 16);
	MemZero(RealStack, StackSize);
	*(ULONG64*)(&ShellcodeBase[6]) = (ULONG64)RealStack + StackSize - 0x28;
	*(ULONG64*)(&ShellcodeBase[0x10]) = (ULONG64)WaitGame;
	HANDLE ThreadHandle; OBJECT_ATTRIBUTES ObjectAttributes; CLIENT_ID ClientID{ };
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	ImpCall(PsCreateSystemThread, &ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, 0, &ClientID, (PKSTART_ROUTINE)ShellcodeBase, 0);
	while (!InterruptedThreadArray && !PreservedStackArray) { Sleep(100); }
	ImpCall(ZwClose, ThreadHandle);
	KFree(ShellcodeBase, sizeof(ThreadStartShellcode));
}
auto null_pfn(PMDL mdl) -> bool /*This function is written by nbq*/
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages) { return false; }

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;
	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		MemCpy(&mdl_pages[i], source_address.VirtualAddress, sizeof(ULONG));
	}
	return true;
}

//if (!intel_driver::CallKernelFunction(iqvw64e_device_handle, &status, address_of_entry_point,mdlptr, param2)) { kdmapper call example
NTSTATUS DriverEntry(PMDL mdl, PVOID KBaseA) // MDL as first param, ntoskrnl.exe base as second
{
	KBase = EPtr(KBaseA);

	ImpSet(KeGetCurrentThread);

	ImpSet(KeDelayExecutionThread);

	ImpSet(MmMapIoSpaceEx);
	ImpSet(MmUnmapIoSpace);
	ImpSet(MmCopyMemory);
	ImpSet(ObfDereferenceObject);
	//ImpSet(RtlGetVersion);

	ImpSet(ExAllocatePoolWithTag);
	ImpSet(ExFreePoolWithTag);

	ImpSet(memcpy);
	ImpSet(memset);
	ImpSet(MmIsAddressValid);

	//ImpSet(PsGetCurrentProcess)
	ImpSet(PsGetProcessSectionBaseAddress);
	ImpSet(PsLookupProcessByProcessId);
	ImpSet(PsCreateSystemThread);
	ImpSet(PsTerminateSystemThread);
	ImpSet(PsGetProcessPeb);

	ImpSet(ZwAllocateVirtualMemory);
	ImpSet(ZwProtectVirtualMemory);
	ImpSet(ZwFreeVirtualMemory);
	ImpSet(ZwQuerySystemInformation);
	ImpSet(ZwClose);


	RetInstruction = FindPattern(KBaseA, E(".text"), E("C3"));
	RopGadgetAddressArray = EPtr(FindPattern(KBaseA, E(".text"), E("48 8B E5 48 8B AD ? ? ? ? 48 81 C4 ? ? ? ? 48 CF"), Random(2, 20)));

	ULONG64 PTE = (ULONG64)FindPattern(KBaseA, E(".text"), E("48 23 C8 48 B8 ? ? ? ? ? ? ? ? 48 03 C1 C3"));
	PTE = *(ULONG64*)(PTE + 5);
	ULONGLONG Mask = (1ll << (PHYSICAL_ADDRESS_BITS - 1)) - 1;
	PDEBase = EPtr((PTE & ~Mask) | ((PTE >> 9) & Mask));
	PTEBase = EPtr(PTE);

	InitializeThread(KBaseA);
	null_pfn(mdl);
	return STATUS_SUCCESS;
}
