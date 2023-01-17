#pragma once
#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))
#define PHYSICAL_ADDRESS_BITS 40
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PTE_SHIFT 3
//__forceinline PMMPTE GetPTEForVA(PVOID Address)
//{
//
//	PMMPTE PDE = (PMMPTE)(((((ULONG64)Address >> PDI_SHIFT) << PTE_SHIFT) & 0x3FFFFFF8ull) + EPtr<ULONG64>(PDEBase));
//
//	if (PDE->u.Hard.LargePage)
//		return PDE;
//
//	return (PMMPTE)(((((ULONG64)Address >> PTI_SHIFT) << PTE_SHIFT) & 0x7FFFFFFFF8ull) + EPtr<ULONG64>(PTEBase));
//}

template <typename A>
 bool IsAddressValid(A Address) {
	return ImpCall(MmIsAddressValid, (PVOID)Address);
}
 void MemCpy(PVOID Dst, PVOID Src, ULONG Size) {
	ImpCall(memcpy, Dst, Src, Size);
}
 void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0) {
	ImpCall(memset, Ptr, Filling, Size);
}

 PVOID KAlloc(ULONG Size, POOL_TYPE PoolType = NonPagedPoolNx) {
	PVOID Buff = ImpCall(ExAllocatePoolWithTag, PoolType, Size, 'KgxD');
	if (Buff) MemZero(Buff, Size); return Buff;
}
 void KFree(PVOID Ptr, ULONG Size = 0) {
	if (Size) MemZero(Ptr, Size);
	ImpCall(ExFreePoolWithTag, Ptr, 'KgxD');
}

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);
	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		char SectName[9]; SectName[8] = 0;
		MemCpy(SectName, pSect->Name, 8);
		if (StrICmp(pSect->Name, Name, true))
		{
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}
	return nullptr;
}
PUCHAR FindPattern(PVOID ModBase, const char* SectName, const char* Pattern, ULONG AddressOffset = 0)
{
	ULONG SectSize = 0; ULONG Offset = 0;
	PUCHAR SectStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);

	PUCHAR ModBuff = (PUCHAR)KAlloc(SectSize); MemCpy(ModBuff, SectStart, SectSize);
	PUCHAR ModuleStart = ModBuff; PUCHAR ModuleEnd = ModBuff + SectSize;

	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');
		if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;

			if (CurPatt[-1] == 0 && Offset++ == AddressOffset)
				break;
		}
		else if (FirstMatch) {
			ModuleStart = FirstMatch;
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	KFree(ModBuff, SectSize);

	return FirstMatch ? (PUCHAR)(((ULONG64)FirstMatch - (ULONG64)ModBuff) + (ULONG64)SectStart) : nullptr;
}