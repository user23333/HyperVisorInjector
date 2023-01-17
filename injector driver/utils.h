void Sleep(LONG64 Milliseconds) {
	LARGE_INTEGER Delay;
	Delay.QuadPart = -Milliseconds * 10000;
	ImpCall(KeDelayExecutionThread, KernelMode, false, &Delay);
}
PVOID NQSI(SYSTEM_INFORMATION_CLASS Class, ULONG* Size = nullptr)
{
NewTry: ULONG ReqSize = 0;
	ImpCall(ZwQuerySystemInformation, Class, nullptr, ReqSize, &ReqSize);
	if (!ReqSize) goto NewTry;

	PVOID pInfo = KAlloc(ReqSize);
	if (!NT_SUCCESS(ImpCall(ZwQuerySystemInformation, Class, pInfo, ReqSize, &ReqSize))) {
		KFree(pInfo, ReqSize); goto NewTry;
	}

	if (Size) *Size = ReqSize;

	return pInfo;
}
HANDLE GetProcessId(const char* ProcName)
{
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation), pInfoCur = pInfo;
	while (true)
	{
		const wchar_t* ProcessName = pInfoCur->ImageName.Buffer;
		if (ImpCall(MmIsAddressValid,(PVOID)ProcessName))
			if (StrICmp(ProcName, ProcessName, true))
				return pInfoCur->UniqueProcessId;

		if (!pInfoCur->NextEntryOffset) break;
		pInfoCur = (PSYSTEM_PROCESS_INFO)((ULONG64)pInfoCur + pInfoCur->NextEntryOffset);
	}
	KFree(pInfo);
	return 0;
}

PVOID GetUserModuleBase(PEPROCESS Process, const char* ModName)
{
	PPEB PEB = ImpCall(PsGetProcessPeb,Process);
	if (!PEB || !PEB->Ldr) return nullptr;
	for (PLIST_ENTRY pListEntry = PEB->Ldr->InLoadOrderModuleList.Flink;
		pListEntry != &PEB->Ldr->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink)
	{
		if (ImpCall(MmIsAddressValid,pListEntry))
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (ImpCall(MmIsAddressValid,pEntry) && ImpCall(MmIsAddressValid,pEntry->BaseDllName.Buffer)) {
				if (StrICmp(ModName, pEntry->BaseDllName.Buffer, true))
					return pEntry->DllBase;
			}
		}
	}
	return nullptr;
}

//PVOID GetImport(PVOID ModBase, const char* Import)
//{
//	if (!ModBase)return nullptr;
//	IMAGE_DOS_HEADER dosHeader = { 0 };
//	_IMAGE_NT_HEADERS64 ntHeaders = { 0 };
//	ReadProcessMemory(  ModBase, &dosHeader, sizeof(dosHeader) );
//	ReadProcessMemory(  PVOID(uintptr_t(ModBase) + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders) );
//	ULONG ImportDescriptorOffset = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
//	if (!ImportDescriptorOffset)return nullptr;
//	for (;; ImportDescriptorOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR))
//	{
//		IMAGE_IMPORT_DESCRIPTOR importDescriptor = { 0 };
//		ReadProcessMemory(  PVOID((ULONG64)ModBase + ImportDescriptorOffset), &importDescriptor, sizeof(importDescriptor) );
//		auto thunkOffset = importDescriptor.OriginalFirstThunk;
//		if (!thunkOffset)break;
//		for (ULONG i = 0UL; ; thunkOffset += sizeof(IMAGE_THUNK_DATA64), ++i)
//		{
//			IMAGE_THUNK_DATA64 thunk = { 0 };
//			ReadProcessMemory(  PVOID((ULONG64)ModBase + thunkOffset), &thunk, sizeof(thunk) );
//			if (!thunk.u1.AddressOfData)
//				break;
//			CHAR name[0xFF] = { 0 };
//			ReadProcessMemory(  PVOID((ULONG64)ModBase + thunk.u1.AddressOfData + FIELD_OFFSET(IMAGE_IMPORT_BY_NAME, Name)), name, sizeof(name) );
//			if (StrICmp(name, Import, true))
//				return (PVOID)((ULONG64)ModBase + importDescriptor.FirstThunk + (i * sizeof(PVOID)));
//		}
//	}
//	return nullptr;
//}

NTSTATUS AllocateMemory(SIZE_T Size, PVOID &Base)
{
	size_t AllocSize = SizeAlign(Size);
	
	return ImpCall(ZwAllocateVirtualMemory,ZwCurrentProcess(), &Base, 0, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//if (Base)
	//{
	//	for (size_t i = 0; i < AllocSize; i += PAGE_SIZE)
	//	{
	//		const auto Addr = (uintptr_t)Base + i;
	//		*(volatile uintptr_t*)(Addr);
	//		GetPTEForVA((PVOID)Addr)->u.Hard.NoExecute = false;
	//	}
	//}
	//return Base;
}
//NTSTATUS AllocateMemoryRW(SIZE_T Size, PVOID& Base)
//{
//	size_t AllocSize = SizeAlign(Size);
//
//	return ImpCall(ZwAllocateVirtualMemory, ZwCurrentProcess(), &Base, 0, &AllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//	//if (Base)
//	//{
//	//	for (size_t i = 0; i < AllocSize; i += PAGE_SIZE)
//	//	{
//	//		const auto Addr = (uintptr_t)Base + i;
//	//		*(volatile uintptr_t*)(Addr);
//	//		GetPTEForVA((PVOID)Addr)->u.Hard.NoExecute = false;
//	//	}
//	//}
//	//return Base;
//}
//NTSTATUS ProtectMemory(PVOID Address, SIZE_T Size, ULONG NewProtect)
//{
//	ULONG OldProtection = 0;
//	return ImpCall(ZwProtectVirtualMemory,ZwCurrentProcess(), &Address, &Size, NewProtect, &OldProtection);
//}
void FreeMemory(PVOID Address, SIZE_T Size)
{
	uintptr_t SizeUL64 = SizeAlign(Size);
	if (!SizeUL64)
		ImpCall(ZwFreeVirtualMemory,ZwCurrentProcess(), (void**)&Address, &SizeUL64, MEM_RELEASE);
	else
		ImpCall(ZwFreeVirtualMemory,ZwCurrentProcess(), (void**)&Address, &SizeUL64, MEM_DECOMMIT);
}
//OSVERSIONINFOW GetOSVersion() {
//	OSVERSIONINFOW OSInfo{ 0 };
//	ImpCall(RtlGetVersion, &OSInfo);	//RtlGetVersion();
//	return OSInfo;
//}
PEPROCESS KiSwapProcess(PEPROCESS NewProcess) {
	auto CurrentThread = ImpCall(KeGetCurrentThread);
	auto ApcState = *(ULONG64*)((ULONG64)CurrentThread + (ULONG64)EPtr(EPtr(0x98)));
	auto OldProcess = *(PEPROCESS*)(ApcState + 0x20);
	*(PEPROCESS*)(ApcState + 0x20) = NewProcess;
	auto DirectoryTableBase = *(ULONG64*)((ULONG64)NewProcess + 0x28);
	__writecr3(DirectoryTableBase);
	return OldProcess;
}


//typedef struct _HANDLE_TABLE
//{
//	ULONG       NextHandleNeedingPool;  //Uint4B
//	LONG        ExtraInfoPages;         //Int4B
//	ULONG64     TableCode;              //Uint8B 
//	PEPROCESS   QuotaProcess;           //Ptr64 _EPROCESS
//	_LIST_ENTRY HandleTableList;        //_LIST_ENTRY
//	ULONG       UniqueProcessId;        //Uint4B
//} HANDLE_TABLE, * PHANDLE_TABLE;
//
//typedef struct _HANDLE_TABLE_ENTRY_INFO
//{
//	ULONG AuditMask;                //Uint4B
//	ULONG MaxRelativeAccessMask;    //Uint4b
//} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;
//
//typedef struct _HANDLE_TABLE_ENTRY
//{
//	union                                           //that special class
//	{
//		ULONG64 VolatileLowValue;                   //Int8B
//		ULONG64 LowValue;                           //Int8B
//		ULONG64 RefCountField;                      //Int8B
//		_HANDLE_TABLE_ENTRY_INFO* InfoTable;        //Ptr64 _HANDLE_TABLE_ENTRY_INFO
//		struct
//		{
//			ULONG64 Unlocked : 1;        //1Bit
//			ULONG64 RefCnt : 16;       //16Bits
//			ULONG64 Attributes : 3;        //3Bits
//			ULONG64 ObjectPointerBits : 44;       //44Bits
//		};
//	};
//	union
//	{
//		ULONG64 HighValue;                          //Int8B
//		_HANDLE_TABLE_ENTRY* NextFreeHandleEntry;   //Ptr64 _HANDLE_TABLE_ENTRY
//	};
//} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;
//ULONG64* resolve(const ULONG64 addressInstruction, const int opcodeBytes, int addressBytes)
//{
//	addressBytes += opcodeBytes;
//	const ULONG32 RelativeOffset = *reinterpret_cast<ULONG32*>(addressInstruction + opcodeBytes);
//	ULONG64* FinalAddress = reinterpret_cast<ULONG64*>(addressInstruction + RelativeOffset + addressBytes);
//	return FinalAddress;
//}
//PHANDLE_TABLE GetPspCidTable()
//{
//	//sig for win 10 21H1
//	uintptr_t PspCidTablePtr = (uintptr_t)FindPattern("PAGE","\x48\x8B\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x49\x89\x87\x00\x00\x00\x00","xxx????x????xxx????");
//
//	if (!PspCidTablePtr)
//		return 0;
//
//	PspCidTablePtr = (uintptr_t)resolve(PspCidTablePtr, 3, 7);
//
//	if (!PspCidTablePtr)
//		return 0;
//
//	return  *(PHANDLE_TABLE*)PspCidTablePtr;
//}
//
//PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(ULONG64* pHandleTable, ULONG64 Handle)
//{
//	ULONG64 tableLevel = Handle & -4;
//
//	if (tableLevel >= *pHandleTable)
//		return 0;
//
//	ULONG64 tableBase = *(pHandleTable + 1);
//	ULONG64 tableIndex = (tableBase & 3);
//
//	switch (tableIndex)
//	{
//	case 0:
//	{
//		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(tableBase + 4 * tableLevel);
//	}
//	case 1:
//	{
//		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(tableBase + 8 * (tableLevel >> 10) - 1) + 4 * (tableLevel & 0x3FF));
//	}
//	case 2:
//	{
//		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(tableBase + 8 * (tableLevel >> 19) - 2) + 8 * ((tableLevel >> 10) & 0x1FF)) + 4 * (tableLevel & 0x3FF));
//	}
//	default:
//		return 0;
//	}
//}
//
//void DriverThread(PVOID context)
//{
	////get current thread id to look up pspcidtable entry
	//HANDLE currentThreadId = PsGetCurrentThreadId();

	////to test if the spoofed return is infact different
	//PETHREAD currentThread;
	//NTSTATUS status = PsLookupThreadByThreadId(currentThreadId, &currentThread);

	//if (!NT_SUCCESS(status))
	//	PsTerminateSystemThread(STATUS_SUCCESS);


	//DebugMessage("[s11] Hiding thread with ID ->%i", currentThreadId);
	//DebugMessage("[s11] Hiding peThread ->%p", currentThread);


	//PHANDLE_TABLE PspCidTable = GetPspCidTable();

	//PHANDLE_TABLE_ENTRY myEntry = ExpLookupHandleTableEntry((ULONG64*)PspCidTable, (LONGLONG)PsGetCurrentThreadId());
	//PETHREAD targetThread = GetThreadToHijack(); //this just grabs a random system thread

	//PHANDLE_TABLE_ENTRY targetEntry = ExpLookupHandleTableEntry((ULONG64*)PspCidTable, (LONGLONG)PsGetThreadId(targetThread));

	////Spoof
	//HANDLE_TABLE_ENTRY _myEntry = *myEntry; //preserve old entry
	//memcpy(myEntry, targetEntry, sizeof(HANDLE_TABLE_ENTRY)); //overwrite
	//DebugMessage("[s11] spoofed thread");

	////pray to allah that they don't check the pid of the thread that PsLookupThreadByThreadId returns
	//PETHREAD queryThread;
	//NTSTATUS status = PsLookupThreadByThreadId(currentThreadId, &queryThread);
	//DebugMessage("[s11] Return from PsLookupThreadByThreadId ->%p", queryThread);

	////restore
	//memcpy(myEntry, &_myEntry, sizeof(HANDLE_TABLE_ENTRY));
	//DebugMessage("[s11] restored entry");

	//PsTerminateSystemThread(STATUS_SUCCESS);
//}
//PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(const ULONG64* pHandleTable, const LONGLONG Handle)
//{
//	ULONGLONG v2; // rdx
//	LONGLONG v3; // r8
//
//	v2 = Handle & 0xFFFFFFFFFFFFFFFC;
//	if (v2 >= *pHandleTable)
//		return 0;
//	v3 = *(pHandleTable + 1);
//	if ((v3 & 3) == 1)
//		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 10) - 1) + 4 * (v2 & 0x3FF));
//	if ((v3 & 3) != 0)
//		return reinterpret_cast<PHANDLE_TABLE_ENTRY>(*reinterpret_cast<ULONG_PTR*>(*reinterpret_cast<ULONG_PTR*>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF)) + 4 * (v2 & 0x3FF));
//	return reinterpret_cast<PHANDLE_TABLE_ENTRY>(v3 + 4 * v2);
//}
//void DestroyPspCidTableEntry(const ULONG64* pPspCidTable, const HANDLE threadId)
//{
//	ULONG64* pHandleTable = reinterpret_cast<ULONG64*>(*pPspCidTable); //deref for pointer to handle table
//	const PHANDLE_TABLE_ENTRY pCidEntry = ExpLookupHandleTableEntry(pHandleTable, reinterpret_cast<LONGLONG>(threadId));
//
//	if (pCidEntry != NULL)
//	{
//		DbgPrintEx(0, 0, "Handle table: %p", pHandleTable);
//		DbgPrintEx(0, 0, "Cid entry: %p", pCidEntry);
//		DbgPrintEx(0, 0, "ObjectPointerBits: %p", pCidEntry->ObjectPointerBits);
//
//		ExDestroyHandle(reinterpret_cast<PHANDLE_TABLE>(pHandleTable), threadId, pCidEntry);
//
//		if (pCidEntry->ObjectPointerBits == 0)
//		{
//			DbgPrintEx(0, 0, "Entry should be removed removed");
//			DbgPrintEx(0, 0, "ObjectPointerBits now: %p", pCidEntry->ObjectPointerBits);
//		}
//	}
//}
//InterruptedThreadArray[0] = EPtr<PKTHREAD>(CurrentThread);
	//PreservedStackArray[0] = EPtr(StackPreserve);
//void InitializeThread(PVOID KBase) {
//	UCHAR ThreadStartShellcode[] = { 0xFA, 0x48, 0x89, 0xE2, 0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
//	UCHAR* ShellcodeBase = (UCHAR*)KAlloc(sizeof(ThreadStartShellcode), NonPagedPool);
//	MemCpy(ShellcodeBase, &ThreadStartShellcode[0], sizeof(ThreadStartShellcode));
//
//	SIZE_T StackSize = 0x1000 * 16;
//	auto RealStack = MmAllocateIndependentPages(KBase, 16);
//
//	MemZero(RealStack, StackSize);
//
//	*(ULONG64*)(&ShellcodeBase[6]) = (ULONG64)RealStack + StackSize - 0x28;
//	*(ULONG64*)(&ShellcodeBase[0x10]) = (ULONG64)WaitGame;
//
//	HANDLE ThreadHandle; OBJECT_ATTRIBUTES ObjectAttributes; CLIENT_ID ClientID{ };
//	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
//	ImpCall(PsCreateSystemThread, &ThreadHandle, THREAD_ALL_ACCESS, &ObjectAttributes, 0, &ClientID, (PKSTART_ROUTINE)ShellcodeBase, 0);
//	while (!InterruptedThreadArray[0] && !PreservedStackArray[0]) { Sleep(100); }
//	ImpCall(ZwClose, ThreadHandle);
//	KFree(ShellcodeBase, sizeof(ThreadStartShellcode));
//}
//PVOID MmAllocateIndependentPages(PVOID KBase, ULONG PageCount)
//{
//	auto MiSystemPartition = (PVOID)RVA(FindPattern(KBase, E(".text"), E("0F 85 ? ? ? ? 48 8D 05 ? ? ? ? 4C 3B D0")), 13);
//	auto MiGetPage = (PVOID)RVA(FindPattern(KBase, E(".text"), E("48 8B 0C C8 E8 ? ? ? ? 48 83 F8 FF")), 9);
//	auto MiRemovePhysicalMemory = (PVOID)RVA(FindPattern(KBase, E(".text"), E("E8 ? ? ? ? 48 83 3D ? ? ? ? ? 75 E9 48 8D ?")), 5);
//	auto MiSystemPteInfo = (PVOID)RVA(FindPattern(KBase, E(".text"), E("4C 2B D1 48 8D 0D ? ? ? ?")), 10);
//	auto MiReservePtes = (PVOID)RVA(FindPattern(KBase, E(".text"), E("48 8B 80 ? ? ? ? 48 89 45 ? E8 ? ? ? ?")), 16);
//
//	MMPTE* PTE = CallPtr<MMPTE*>(MiReservePtes, MiSystemPteInfo, PageCount);
//
//	if (!PTE) return nullptr;
//
//#define PTE_SHIFT 3
//#define VA_SHIFT (63 - 47)
//#define MiGetVirtualAddressMappedByPte(PTE) ((PVOID)((LONG_PTR)(((LONG_PTR)(PTE) - EPtr<ULONG64>(PTEBase)) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT))
//
//	auto VA = MiGetVirtualAddressMappedByPte(PTE);
//
//	for (SIZE_T i = 0; i < PageCount; i++)
//	{
//	NewTry:
//		auto PFN = CallPtr<ULONG64>(MiGetPage, MiSystemPartition, 0ull, 8ull);
//
//		if (PFN == -1) goto NewTry;
//
//		ULONG64 PfnSize = 0x1000; PfnSize = PfnSize >> 12;
//		CallPtr<void>(MiRemovePhysicalMemory, PFN, PfnSize);
//
//		PTE->u.Hard.Valid = 1;
//		PTE->u.Hard.Owner = 0;
//		PTE->u.Hard.Write = 1;
//		PTE->u.Hard.NoExecute = 0;
//		PTE->u.Hard.PageFrameNumber = PFN;
//
//		++PTE;
//	}
//
//	return VA;
//}

//PVOID GetUserModuleBase(PEPROCESS Process, const char* ModName, ULONG* ModSize = nullptr)
//{
//	PPEB PPEB = ImpCall(PsGetProcessPeb, Process);
//
//	if (IsAddressValid(PPEB)) {
//		PEB PEB_Data;
//		MemCpy(&PEB_Data, PPEB, sizeof(PEB));
//
//		if (IsAddressValid(PEB_Data.Ldr)) {
//			PEB_LDR_DATA Ldr;
//			MemCpy(&Ldr, PEB_Data.Ldr, sizeof(PEB_LDR_DATA));
//
//			PLIST_ENTRY LdrListHead = Ldr.InLoadOrderModuleList.Flink;
//			PLIST_ENTRY LdrCurrentNode = Ldr.InLoadOrderModuleList.Flink;
//
//			if (IsAddressValid(LdrListHead)) {
//				do
//				{
//					LDR_DATA_TABLE_ENTRY ListEntry;
//					MemCpy(&ListEntry, LdrCurrentNode, sizeof(LDR_DATA_TABLE_ENTRY));
//				
//					if (ListEntry.BaseDllName.Length > 0 && StrICmp(ModName, ListEntry.BaseDllName.Buffer, true)) {
//						if (ModSize) *ModSize = ListEntry.SizeOfImage;
//						return ListEntry.DllBase;
//					}
//				
//					LdrCurrentNode = ListEntry.InLoadOrderLinks.Flink;
//				} while (LdrListHead != LdrCurrentNode);
//			}
//		}
//	}
//
//	return nullptr;
//}
//template<typename ReadType>
//__forceinline ReadType Read(ULONG64 Addr)
//{
//	ReadType ReadData{};
//	if (Addr && ImpCall(MmIsAddressValid, (PVOID)Addr))
//	{
//		ReadData = *(ReadType*)Addr;
//	}
//
//	return ReadData;
//}
//bool ReadArr(ULONG64 Addr, PVOID Buff, ULONG Size)
//{
//	if (ImpCall(MmIsAddressValid, (PVOID)Addr))
//	{
//		MemCpy(Buff, (PVOID)Addr, Size);
//		return true;
//	}
//
//	return false;
//}
//template<typename WriteType>
//void Write(ULONG64 Addr, WriteType Data)
//{
//	if (ImpCall(MmIsAddressValid, (PVOID)Addr))
//	{
//		*(WriteType*)Addr = Data;
//	}
//}
//void WriteArr(ULONG64 Addr, PVOID Buff, ULONG Size)
//{
//	if (ImpCall(MmIsAddressValid, (PVOID)Addr))
//	{
//		MemCpy((PVOID)Addr, Buff, Size);
//	}
//}