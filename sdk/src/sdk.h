#pragma once

// Things we probably want
#include <stdbool.h>
#include <stddef.h>
#include <float.h>
#include <stdint.h>

// Type defs
//
// Windows is retarded. Some of these are fucking pointless but 
// its easier to just define them rather than changing the structs.
typedef int BOOL;
typedef void *PVOID;
typedef void *LPVOID;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef unsigned short USHORT;
typedef wchar_t WCHAR;
typedef unsigned long ULONG;
typedef char CHAR;
typedef unsigned long ULONG_PTR; // on 64bit this is unsigned __int64
typedef unsigned short WORD;
typedef long LONG;
typedef unsigned char UCHAR;

// Additional
typedef PVOID HANDLE;
typedef HANDLE HINSTANCE;
typedef WCHAR *PWSTR;
typedef CHAR *PCHAR;
typedef UCHAR *PUCHAR;
typedef ULONG *PULONG;
typedef USHORT *PUSHORT;
typedef DWORD *PDWORD;
typedef ULONG_PTR SIZE_T;


#include "api/api.h"