#pragma once

#include "../sdk.h"

// String.c
int strlen(const char* str);
BOOL strcmp(const char* str1,const char* str2);

// api.c
PVOID GetKernel32Base();
PVOID GetProcAddress(PVOID dllBase, const char* name);


///////////// WINDOWS API /////////////


// kernel32.dll
void Beep(DWORD freq, DWORD dur);
HANDLE GetProcessHeap();
LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);