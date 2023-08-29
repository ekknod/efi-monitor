#include <Windows.h>
#include <intrin.h>
#include "globals.h"

typedef ULONG_PTR QWORD;

void SwapMemory(QWORD BaseAddress, QWORD ImageSize, QWORD NewBase)
{
	INT32 current_location = (INT32)((QWORD)_ReturnAddress() - BaseAddress);

	//
	// copy currently loaded image to new section
	//
	MemCopy((void *)NewBase, (void *)BaseAddress, ImageSize);

	//
	// swap memory
	//
	*(QWORD*)(_AddressOfReturnAddress()) = NewBase + current_location;
}

QWORD get_winload_base(QWORD return_address)
{
	while (*(unsigned short*)return_address != IMAGE_DOS_SIGNATURE)
		return_address = return_address - 1;

	return (QWORD)return_address;
}

static int strcmpi_imp(const char *cs, const char *ct)
{
	unsigned char c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}

void MemCopy(void* dest, void* src, QWORD size)
{
	for (unsigned char* d = (unsigned char*)dest, *s = (unsigned char*)src; size--; *d++ = *s++)
		;
}

static int wcscmpi_imp(const wchar_t *cs, const wchar_t *ct)
{
	unsigned short c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}


QWORD GetExportByName(QWORD base, const char* export_name)
{
	QWORD a0;
	DWORD a1[4];

	a0 = base + *(unsigned short*)(base + 0x3C);
	a0 = base + *(DWORD*)(a0 + 0x88);
	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {
		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (strcmpi_imp((const char *)a0, export_name) == 0) {
			return (base + *(DWORD*)(base + a1[1] + (*(unsigned short*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}
	}
	return 0;
}

QWORD get_pe_entrypoint(QWORD base)
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
	return base + nt->OptionalHeader.AddressOfEntryPoint;
}

void pe_resolve_imports(QWORD ntoskrnl, QWORD base)
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);

	DWORD import_directory =
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
		.VirtualAddress;

	if (import_directory) {
		IMAGE_IMPORT_DESCRIPTOR* import_descriptor =
			(IMAGE_IMPORT_DESCRIPTOR*)(base + import_directory);



		for (; import_descriptor->FirstThunk; ++import_descriptor) {

			if (import_descriptor->FirstThunk == 0)
				break;

			IMAGE_THUNK_DATA64* thunk =
				(IMAGE_THUNK_DATA64*)(base +
					import_descriptor->FirstThunk);

			if (thunk == 0)
				break;

			if (import_descriptor->OriginalFirstThunk == 0)
				break;

			IMAGE_THUNK_DATA64* original_thunk =
				(IMAGE_THUNK_DATA64*)(base +
					import_descriptor->OriginalFirstThunk);

			for (; thunk->u1.AddressOfData; ++thunk, ++original_thunk) {
				UINT64 import = GetExportByName(
					(QWORD)ntoskrnl,
					((IMAGE_IMPORT_BY_NAME*)(base +
						original_thunk->u1.AddressOfData))
					->Name);

				thunk->u1.Function = import;
			}
		}

	}

}

void pe_clear_headers(QWORD base)
{
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
	for (DWORD i = nt->OptionalHeader.SizeOfHeaders; i--;)
	{
		((unsigned char*)base)[i] = (unsigned char)(i + 4 - ((unsigned char*)( base ))[i]) ;
	}
}

typedef struct _UNICODE_STRING {
	UINT16 Length;
	UINT16 MaximumLength;
	wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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
} KLDR_DATA_TABLE_ENTRY;

QWORD GetModuleEntry(LIST_ENTRY* entry, const wchar_t * name)
{
	LIST_ENTRY *list = entry;
	while ((list = list->Flink) != entry) {
		KLDR_DATA_TABLE_ENTRY *module =
			CONTAINING_RECORD(list, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (module && wcscmpi_imp((wchar_t*)module->BaseImageName.Buffer, name) == 0)
		{
			return (QWORD)module->ImageBase;
		}
	}
	return NULL;
}

static int CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return 0;
	return 1;
}

static QWORD strleni(const char *s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

static void *FindPatternEx(unsigned char* base, QWORD size, unsigned char* pattern, unsigned char* mask)
{
	size -= strleni((const char *)mask);
	for (QWORD i = 0; i <= size; ++i) {
		void* addr = &base[i];
		if (CheckMask((unsigned char *)addr, pattern, mask))
			return addr;
	}
	return 0;
}

QWORD FindPattern(QWORD base, unsigned char* pattern, unsigned char* mask)
{
	if (base == 0)
	{
		return 0;
	}

	QWORD nt_header = (QWORD)*(DWORD*)(base + 0x03C) + base;
	if (nt_header == base)
	{
		return 0;
	}

	WORD machine = *(WORD*)(nt_header + 0x4);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(nt_header + 0x06); i++) {
		QWORD section = section_header + ((QWORD)i * 40);

		DWORD section_characteristics = *(DWORD*)(section + 0x24);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			QWORD virtual_address = base + (QWORD)*(DWORD*)(section + 0x0C);
			DWORD virtual_size = *(DWORD*)(section + 0x08);

			void *found_pattern = FindPatternEx( (unsigned char*)virtual_address, virtual_size, pattern, mask);
			if (found_pattern)
			{
				return (QWORD)found_pattern;
			}
		}
	}
	return 0;
}

QWORD GetExport(QWORD base, const char *name)
{
	QWORD a0;
	DWORD a1[4];

	a0 = base + *(unsigned short*)(base + 0x3C);
	if (a0 == base)
	{
		return 0;
	}


	WORD machine = *(WORD*)(a0 + 0x4);

	a0 = machine == 0x8664 ? base + *(DWORD*)(a0 + 0x88) : base + *(DWORD*)(a0 + 0x78);

	if (a0 == base)
	{
		return 0;
	}


	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {
		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (strcmpi_imp((const char *)a0, name) == 0)
		{
			return (base + *(DWORD*)(base + a1[1] + (*(unsigned short*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}
	}
	return 0;
}


