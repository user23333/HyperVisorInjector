extern "C"
{
	NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, PVOID OutBuff, ULONG BuffSize, PULONG OutSize);
	//NTKERNELAPI NTSTATUS ZwSetSystemInformation(SYSTEM_INFORMATION_CLASS SystemInformation, PVOID Buff, ULONG Size);
//	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
	//NTKERNELAPI const char* PsGetProcessImageFileName(PEPROCESS Process);
	//NTKERNELAPI NTSTATUS KeUserModeCallback(ULONG, PVOID, ULONG, PVOID, PVOID);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
	NTKERNELAPI NTSYSAPI NTSTATUS ZwProtectVirtualMemory(HANDLE, PVOID*, SIZE_T*, ULONG, PULONG);
	

}

PVOID GetProcAddress(PVOID ModBase, const char* Name)
{
	PIMAGE_NT_HEADERS64 NT_Head = NT_HEADER(ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);
	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];
		if (StrICmp(Name, ExpName, true))
			return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}

	return nullptr;
}

PVOID KBase;

#define ImpDef(Func) using Func##Def = decltype(&Func); Func##Def Func##Fn = nullptr;
#define ImpSet(Func) Func##Fn = (Func##Def)EPtr(GetProcAddress(EPtr(KBase), E(#Func)));

//PKTHREAD ;
PVOID PreservedStackArray, RopGadgetAddressArray, InterruptedThreadArray;
extern "C" {
	PVOID RetInstruction, RopGadgetAddress;
	void* CalloutInterrupt(void*, void*, size_t, size_t, void*, void*, void*, void*, ...);
	void* CalloutReturn(CONTEXT_RETURN*);
}
ImpDef(KeGetCurrentThread);
ImpDef(KeDelayExecutionThread);

ImpDef(MmMapIoSpaceEx);
ImpDef(MmUnmapIoSpace);
ImpDef(MmCopyMemory);
ImpDef(ObfDereferenceObject);
//ImpDef(RtlGetVersion);

ImpDef(ExAllocatePoolWithTag);
ImpDef(ExFreePoolWithTag);

ImpDef(memcpy);
ImpDef(memset);
ImpDef(MmIsAddressValid);

//ImpDef(PsGetCurrentProcess);
ImpDef(PsGetProcessSectionBaseAddress);
ImpDef(PsLookupProcessByProcessId);
ImpDef(PsCreateSystemThread);
ImpDef(PsTerminateSystemThread);
ImpDef(PsGetProcessPeb);

ImpDef(ZwAllocateVirtualMemory);
ImpDef(ZwProtectVirtualMemory);
ImpDef(ZwFreeVirtualMemory);
ImpDef(ZwQuerySystemInformation);
ImpDef(ZwClose);
template<typename Ret = void*, typename A1 = void*, typename A2 = void*, typename A3 = void*, typename A4 = void*, typename... Stack>
Ret CallPtr(PVOID Func, A1 a1 = A1{}, A2 a2 = A2{}, A3 a3 = A3{}, A4 a4 = A4{}, Stack... args) {
	//for (int i = 0; i < 2; i++)   used to call functions from different threads
	//{
		//if (EPtr(InterruptedThreadArray) == KeGetCurrentThread()) {
	if (EPtr(InterruptedThreadArray) == PVOID(KeGetCurrentThread())) {// comparison is necessary because the impcall is used before the thread is created
		RopGadgetAddress = EPtr(RopGadgetAddressArray);
		return (Ret)CalloutInterrupt(Func, EPtr(PreservedStackArray), sizeof...(Stack), CALLOUT_ENABLE_INTERRUPT_FLAG, (void*)a1, (void*)a2, (void*)a3, (void*)a4, args...);
	}
		//}
	//}

	return ((Ret(__fastcall*)(...))Func)(a1, a2, a3, a4, args...);
}


#define ImpCall(Func, ...) CallPtr<decltype(Func(__VA_ARGS__))>(EPtr(Func##Fn), __VA_ARGS__)

