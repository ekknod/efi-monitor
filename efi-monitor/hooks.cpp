#include <ntifs.h>
#include "globals.h"
#include <intrin.h>

namespace hooks
{
	BOOLEAN initialize(void);


	void *  __cdecl sub_MmCopyMemory(void * _Dst, int _Val, QWORD _Size, ULONG flags);
}

PCWSTR GetCallerModuleName(QWORD address);

//
// sub_MmCopyMemory (hooks memset call in MmCopyMemory function)
//
void *  __cdecl hooks::sub_MmCopyMemory(void * _Dst, int _Val, QWORD _Size, ULONG flags)
{
	//
	// warning.. because we are dumb and hooking memset instead of directly MmCopyMemory, we have to resolve parameters from stack.
	// if you change anything from this hook, there is chance you have to correct some of these offsets.
	// these offsets can be found from our bootx64.efi binary sub_180001078 (sub_MmCopyMemory)
	// 
	// pros:
	// - works as good anti paste
	// - only 4 byte change for ntoskrnl.exe
	// - no obvious looking trampoline
	// 
	// cons: extra work,potentially less compatibility
	// 
	//
	QWORD rsp = (QWORD)_AddressOfReturnAddress();
	QWORD TargetAddress = rsp + 0x18;  // mov     [rax+18h], rsi
	QWORD SourceAddress = rsp + 0x08;  // mov     [rax+8], rbx
	QWORD NumberOfBytes = rsp - 0x08;  // push    r14
	
	//
	// walk back to MmCopyMemory
	//
	rsp = rsp + 0x08;  // call memset
	rsp = rsp + 0x130; // sub rsp, 130h
	rsp = rsp + 0x08;  // push rbp
	rsp = rsp + 0x08;  // push rsi
	rsp = rsp + 0x08;  // push rdi
	rsp = rsp + 0x08;  // push r12
	rsp = rsp + 0x08;  // push r13
	rsp = rsp + 0x08;  // push r14
	rsp = rsp + 0x08;  // push r15
	QWORD return_address = *(QWORD*)(rsp);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%ws][MmCopyMemory](0x%llx, 0x%llx, %s, %ld)\n",
		GetCallerModuleName(return_address),
		*(QWORD*)TargetAddress,
		*(QWORD*)SourceAddress,
		flags == MM_COPY_MEMORY_PHYSICAL ? "MM_COPY_MEMORY_PHYSICAL" : "MM_COPY_MEMORY_VIRTUAL",
		*(DWORD*)NumberOfBytes
		);

	return memset(_Dst, _Val, _Size);
}

BOOLEAN hooks::initialize(void)
{

	//
	// MmCopyMemory->memset hook
	//
	QWORD memset_address = (QWORD)MmCopyMemory + 0x58;
	if (*(unsigned char*)(memset_address) == 0xE8)
	{
		int fixed_address = 0;
		QWORD hook_routine = (QWORD)hooks::sub_MmCopyMemory;
		if (hook_routine > memset_address)
		{
			fixed_address = (int)(hook_routine - memset_address);
		}
		else
		{
			fixed_address = (int)(memset_address - hook_routine);
		}
		*(int*)(memset_address + 1) = (int)fixed_address - 5;
		return TRUE;
	}
	return FALSE;
}

typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	UINT32 ExceptionTableSize;
	VOID* GpValue;
	VOID* NonPagedDebugInfo;
	VOID* ImageBase;
	VOID* EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullImageName;
	UNICODE_STRING BaseImageName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//
// taken from https://github.com/ekknod/Anti-Cheat-TestBench/blob/main/main.c (IsInValidRange)
//
extern "C" __declspec(dllimport) LIST_ENTRY *PsLoadedModuleList;
PCWSTR GetCallerModuleName(QWORD address)
{
	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pEntry->ImageBase == 0)
			continue;

		if (address >= (QWORD)pEntry->ImageBase && address <= (QWORD)((QWORD)pEntry->ImageBase + pEntry->SizeOfImage + 0x1000))
		{			
			return (PWCH)pEntry->BaseImageName.Buffer;
		}

	}
	return L"unknown";
}
