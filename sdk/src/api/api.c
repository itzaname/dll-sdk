#include "api.h"
#include "pe.h"

// Windef
#define CONTAINING_RECORD(address, type, field) ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))

// Windows PEB structs
typedef void (__stdcall *PPS_POST_PROCESS_INIT_ROUTINE) (void);

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY  *Flink;
  struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID Reserved3[2];
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	} u;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// GCC Implementation of __readfsdword in VC
DWORD __readfsdword(DWORD Offset)
{
	DWORD value;
	__asm__ __volatile__("movl %%fs:%a[Offset], %k[value]" : [value] "=r" (value) : [Offset] "ir" (Offset));
	return value;
}

// Gets the base address of kernel32.dll in memory using the PEB of the process
PVOID GetKernel32Base()
{
	PLDR_DATA_TABLE_ENTRY Ldr;
	PPEB Peb = (PPEB)__readfsdword(0x30);

	Ldr = CONTAINING_RECORD(Peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Get the first entry (process executable)
	Ldr = CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // Second entry (ntdll)
	Ldr = CONTAINING_RECORD(Ldr->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks.Flink); // kernel32 is located at third entry

	// Now we can return the base
	return Ldr->DllBase;
}

// Manual implementation of getting exports from DLLs in memory
PVOID GetProcAddress(PVOID dllBase, const char* name)
{
	PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((PVOID)dllBase + pIDH->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((PVOID)dllBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PULONG Function = (PULONG)((PVOID)dllBase + pIED->AddressOfFunctions);
	PULONG Name = (PULONG)((PVOID)dllBase + pIED->AddressOfNames);
	PUSHORT Ordinal = (PUSHORT)((PVOID)dllBase + pIED->AddressOfNameOrdinals);

	for (int i = 0; i < pIED->NumberOfNames; i++)
	{
		if (strcmp((PVOID)dllBase + Name[i],name) == 1)
			return (PVOID)dllBase + Function[Ordinal[i]];
	}

	return NULL;
}


